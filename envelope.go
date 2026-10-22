package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// A Sealer wraps a 32-byte content key with a hardware key.
//
//   - Wrap is a public-key operation: it never prompts. That is what lets the
//     watcher move a key into the vault silently, exactly like the Mac version.
//   - Unwrap is a private-key operation inside the TPM. For the guarded sealer it
//     raises a Windows Hello prompt that shows `prompt`; for the quiet sealer it
//     does not prompt.
type Sealer interface {
	Name() string
	Wrap(cek []byte) ([]byte, error)
	Unwrap(wrapped []byte, prompt string) ([]byte, error)
}

// PinSigner signs the account pin with a second Windows Hello key. Verification
// uses the public key read live from the TPM key, never from a file on disk, so
// malware running as the user cannot forge a pin without a Hello approval.
type PinSigner interface {
	Sign(digest []byte, prompt string) ([]byte, error)
	PublicKey() (*rsa.PublicKey, error)
}

const (
	kindGuarded = "hello" // Windows Hello on every unwrap
	kindQuiet   = "quiet" // TPM (or DPAPI fallback), no prompt
)

// Envelope is the on-disk format. Everything outside CT is non-secret metadata.
type Envelope struct {
	V       int               `json:"v"`
	Kind    string            `json:"kind"`
	Purpose string            `json:"purpose"`
	Profile string            `json:"profile"`
	Sealer  string            `json:"sealer"`
	Wrapped []byte            `json:"wrapped"`
	Nonce   []byte            `json:"nonce"`
	CT      []byte            `json:"ct"`
	Created time.Time         `json:"created"`
	Meta    map[string]string `json:"meta,omitempty"`
}

func envelopeAAD(kind, purpose, profile string) []byte {
	return []byte("aws-cli-zsp/v1/" + kind + "/" + purpose + "/" + profile)
}

func seal(s Sealer, kind, purpose, profile string, payload []byte, meta map[string]string) (*Envelope, error) {
	cek := make([]byte, 32)
	if _, err := rand.Read(cek); err != nil {
		return nil, err
	}
	defer zero(cek)
	wrapped, err := s.Wrap(cek)
	if err != nil {
		return nil, fmt.Errorf("wrap with %s: %w", s.Name(), err)
	}
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Envelope{
		V: 1, Kind: kind, Purpose: purpose, Profile: profile, Sealer: s.Name(),
		Wrapped: wrapped, Nonce: nonce,
		CT:      gcm.Seal(nil, nonce, payload, envelopeAAD(kind, purpose, profile)),
		Created: time.Now().UTC(), Meta: meta,
	}, nil
}

func (e *Envelope) open(s Sealer, prompt string) ([]byte, error) {
	if e.V != 1 {
		return nil, fmt.Errorf("unsupported envelope version %d", e.V)
	}
	cek, err := s.Unwrap(e.Wrapped, prompt)
	if err != nil {
		return nil, err
	}
	defer zero(cek)
	if len(cek) != 32 {
		return nil, errors.New("unwrapped key has the wrong length")
	}
	block, _ := aes.NewCipher(cek)
	gcm, _ := cipher.NewGCM(block)
	pt, err := gcm.Open(nil, e.Nonce, e.CT, envelopeAAD(e.Kind, e.Purpose, e.Profile))
	if err != nil {
		return nil, errors.New("sealed file failed its integrity check (tampered, or sealed on another PC)")
	}
	return pt, nil
}

func writeEnvelope(path string, e *Envelope) error {
	b, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return err
	}
	if err := writeFileAtomic(path, b, 0o600); err != nil {
		return err
	}
	// Paranoid read-back: nothing leaves ~/.aws until the sealed copy on disk is
	// byte-for-byte what we meant to write and still parses.
	back, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read back sealed file: %w", err)
	}
	if string(back) != string(b) {
		return errors.New("sealed file did not read back identically")
	}
	var chk Envelope
	if err := json.Unmarshal(back, &chk); err != nil || len(chk.CT) == 0 || len(chk.Wrapped) == 0 {
		return errors.New("sealed file did not parse on read-back")
	}
	return nil
}

func readEnvelope(path string) (*Envelope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("%s is not a valid sealed file: %w", path, err)
	}
	return &e, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
