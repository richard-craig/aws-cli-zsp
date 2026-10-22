package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
)

// splitSealer is the service-mode guarded sealer.
//
// The content key is split: CEK = K1 XOR K2.
//   - K1 is wrapped to the USER's Windows Hello public key. Only the user's TPM
//     can unwrap it, and only after a Hello gesture, in the user's own session.
//   - K2 is wrapped by the BROKER's quiet key. Only the service can unwrap it.
//
// Neither half alone reveals anything. Malware running as the user can phish a
// Hello prompt and obtain K1, but K1 without K2 is useless, so the most it can
// get is a session the broker chooses to issue. An administrator who takes over
// the broker gets K2, but still needs the user's Hello gesture for K1.
//
// Wrapping needs only public material, so the broker seals keys without a prompt.
type splitSealer struct {
	pub   *rsa.PublicKey // user's Windows Hello vault key (public half)
	quiet Sealer         // broker's TPM/DPAPI key
	ui    UI             // asks the connected client to do the Hello unwrap
}

type splitBlob struct {
	V  int    `json:"v"`
	K1 []byte `json:"k1"` // RSA-PKCS1v15 to the Hello key
	K2 []byte `json:"k2"` // wrapped by the broker key
}

func (s *splitSealer) Name() string { return "hello+broker" }

func (s *splitSealer) Wrap(cek []byte) ([]byte, error) {
	if s.pub == nil {
		return nil, errors.New("not enrolled: run `zsp setup` as this user first")
	}
	if len(cek) != 32 {
		return nil, errors.New("content key must be 32 bytes")
	}
	k1 := make([]byte, 32)
	if _, err := rand.Read(k1); err != nil {
		return nil, err
	}
	defer zero(k1)
	k2 := make([]byte, 32)
	for i := range k2 {
		k2[i] = cek[i] ^ k1[i]
	}
	defer zero(k2)
	w1, err := rsa.EncryptPKCS1v15(rand.Reader, s.pub, k1)
	if err != nil {
		return nil, err
	}
	w2, err := s.quiet.Wrap(k2)
	if err != nil {
		return nil, fmt.Errorf("broker key: %w", err)
	}
	return json.Marshal(splitBlob{V: 1, K1: w1, K2: w2})
}

func (s *splitSealer) Unwrap(blob []byte, prompt string) ([]byte, error) {
	var b splitBlob
	if err := json.Unmarshal(blob, &b); err != nil || b.V != 1 {
		return nil, errors.New("sealed key is not a split-key envelope (sealed in user mode? run `zsp service migrate`)")
	}
	k2, err := s.quiet.Unwrap(b.K2, "")
	if err != nil {
		return nil, fmt.Errorf("broker key: %w", err)
	}
	defer zero(k2)
	if s.ui == nil {
		return nil, errors.New("no client connected to approve with Windows Hello")
	}
	k1, err := s.ui.HelloUnwrap(b.K1, prompt)
	if err != nil {
		return nil, err
	}
	defer zero(k1)
	if len(k1) != 32 || len(k2) != 32 {
		return nil, errors.New("key halves have the wrong length")
	}
	cek := make([]byte, 32)
	for i := range cek {
		cek[i] = k1[i] ^ k2[i]
	}
	return cek, nil
}

func encodePublicKey(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func decodePublicKey(p string) (*rsa.PublicKey, error) {
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		return nil, errors.New("not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PublicKey)
	if !ok || rk.N.BitLen() < 2048 {
		return nil, errors.New("public key must be RSA-2048 or larger")
	}
	return rk, nil
}
