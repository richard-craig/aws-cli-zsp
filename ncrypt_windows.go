//go:build windows

package main

// CNG / NCrypt plumbing for two hardware-backed keys:
//
//  1. Windows Hello keys in the "Microsoft Passport Key Storage Provider".
//     These are the same TPM-backed NGC keys that sit behind Windows Hello and
//     platform passkeys. Private-key use (decrypt or sign) raises the Windows
//     Hello prompt (face, fingerprint or PIN) and the key never leaves the TPM.
//     NgcCacheType=AuthMandatory + PinCacheIsGestureRequired make every single
//     use ask, rather than riding a cached unlock.
//
//  2. A quiet key in the "Microsoft Platform Crypto Provider" (plain TPM 2.0,
//     no UI) for the session cache and audit anchor, so an hour of commands
//     does not prompt again. If no TPM is available it falls back to DPAPI.
//
// The Passport key-creation shape (NGC-style name, property set, cache type
// fallback) follows ByteNess keyring's winhello backend (MIT), the maintained
// aws-vault fork, which validated it on real hardware.

import (
	"crypto/rsa"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"os/user"
	"syscall"
	"unsafe"
)

type ncHandle uintptr

var (
	modNCrypt = syscall.NewLazyDLL("ncrypt.dll")

	procOpenStorageProvider = modNCrypt.NewProc("NCryptOpenStorageProvider")
	procOpenKey             = modNCrypt.NewProc("NCryptOpenKey")
	procCreatePersistedKey  = modNCrypt.NewProc("NCryptCreatePersistedKey")
	procSetProperty         = modNCrypt.NewProc("NCryptSetProperty")
	procFinalizeKey         = modNCrypt.NewProc("NCryptFinalizeKey")
	procEncrypt             = modNCrypt.NewProc("NCryptEncrypt")
	procDecrypt             = modNCrypt.NewProc("NCryptDecrypt")
	procSignHash            = modNCrypt.NewProc("NCryptSignHash")
	procExportKey           = modNCrypt.NewProc("NCryptExportKey")
	procDeleteKey           = modNCrypt.NewProc("NCryptDeleteKey")
	procFreeObject          = modNCrypt.NewProc("NCryptFreeObject")
)

const (
	providerPassport = "Microsoft Passport Key Storage Provider"
	providerPlatform = "Microsoft Platform Crypto Provider"

	propLength           = "Length"
	propKeyUsage         = "Key Usage"
	propNgcCacheType     = "NgcCacheType"
	propNgcCacheLegacy   = "NgcCacheTypeProperty"
	propGestureRequired  = "PinCacheIsGestureRequired"
	propUseContext       = "Use Context"
	propHWND             = "HWND Handle"
	allowDecrypt         = 0x1
	allowSigning         = 0x2
	ngcAuthMandatory     = 0x1
	bcryptPadPKCS1       = 0x2
	ncryptSilentFlag     = 0x40
	rsaPublicBlobType    = "RSAPUBLICBLOB"
	bcryptRSAPublicMagic = 0x31415352 // 'RSA1'
)

var (
	errBadKeyset     = syscall.Errno(0x80090016)
	errNoKey         = syscall.Errno(0x8009000d)
	errNotFound      = syscall.Errno(0x80090011)
	errNotSupported  = syscall.Errno(0x80090029)
	errDeviceNotRdy  = syscall.Errno(0x80090030)
	errUserCancelled = syscall.Errno(0x80090036)
	errKeyNotFound   = errors.New("key not found")
)

type ncryptError struct {
	op   string
	code syscall.Errno
}

func (e *ncryptError) Error() string {
	switch e.code {
	case errUserCancelled:
		return "cancelled at the Windows Hello prompt"
	case errNotSupported, errDeviceNotRdy:
		return fmt.Sprintf("%s: Windows Hello is not ready (0x%08X). Set up a Windows Hello PIN, face or fingerprint in Settings > Accounts > Sign-in options", e.op, uint32(e.code))
	}
	return fmt.Sprintf("%s failed: 0x%08X %v", e.op, uint32(e.code), e.code)
}

func ncCall(op string, p *syscall.LazyProc, args ...uintptr) error {
	r, _, _ := p.Call(args...)
	if r == 0 {
		return nil
	}
	e := syscall.Errno(r)
	if e == errBadKeyset || e == errNoKey || e == errNotFound {
		return errKeyNotFound
	}
	return &ncryptError{op: op, code: e}
}

func utf16p(s string) *uint16 {
	p, _ := syscall.UTF16PtrFromString(s)
	return p
}

func ncOpenProvider(name string) (ncHandle, error) {
	var h ncHandle
	err := ncCall("NCryptOpenStorageProvider", procOpenStorageProvider, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16p(name))), 0)
	return h, err
}

func ncFree(h ncHandle) {
	if h != 0 {
		procFreeObject.Call(uintptr(h))
	}
}

func ncOpenKey(prov ncHandle, name string) (ncHandle, error) {
	var h ncHandle
	err := ncCall("NCryptOpenKey", procOpenKey, uintptr(prov), uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(utf16p(name))), 0, 0)
	return h, err
}

func ncSetBytes(h ncHandle, prop string, val []byte) error {
	var p uintptr
	if len(val) > 0 {
		p = uintptr(unsafe.Pointer(&val[0]))
	}
	return ncCall("NCryptSetProperty("+prop+")", procSetProperty, uintptr(h), uintptr(unsafe.Pointer(utf16p(prop))), p, uintptr(len(val)), 0)
}

func ncSetU32(h ncHandle, prop string, v uint32) error {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return ncSetBytes(h, prop, b[:])
}

func ncSetString(h ncHandle, prop, s string) error {
	u, _ := syscall.UTF16FromString(s)
	b := unsafe.Slice((*byte)(unsafe.Pointer(&u[0])), len(u)*2)
	return ncSetBytes(h, prop, b)
}

func ncSetHWND(h ncHandle) {
	if hwnd := promptOwnerHWND(); hwnd != 0 {
		v := hwnd
		b := unsafe.Slice((*byte)(unsafe.Pointer(&v)), unsafe.Sizeof(v))
		_ = ncSetBytes(h, propHWND, b)
	}
}

// ncTwoCall runs the NCrypt "ask for size, then fill" pattern used by
// NCryptEncrypt / NCryptDecrypt / NCryptSignHash.
func ncCrypt(op string, p *syscall.LazyProc, key ncHandle, in []byte, padding unsafe.Pointer, flags uint32) ([]byte, error) {
	if len(in) == 0 {
		return nil, errors.New(op + ": empty input")
	}
	var n uint32
	if err := ncCall(op, p, uintptr(key), uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)), uintptr(padding), 0, 0, uintptr(unsafe.Pointer(&n)), uintptr(flags)); err != nil {
		return nil, err
	}
	out := make([]byte, n)
	if err := ncCall(op, p, uintptr(key), uintptr(unsafe.Pointer(&in[0])), uintptr(len(in)), uintptr(padding), uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(unsafe.Pointer(&n)), uintptr(flags)); err != nil {
		return nil, err
	}
	return out[:n], nil
}

// ---------------------------------------------------------------------------------
// Windows Hello (Passport) keys

const (
	passportDomain    = "aws-cli-zsp"
	passportNamespace = "vault"
	logicalVaultKey   = "vault-key"
	logicalPinKey     = "pin-key"
)

func passportKeyName(logical string) (string, error) {
	u, err := user.Current()
	if err != nil || u.Uid == "" {
		return "", fmt.Errorf("cannot read the current user's SID: %v", err)
	}
	return fmt.Sprintf("%s//%s/%s/%s", u.Uid, passportDomain, passportNamespace, logical), nil
}

type helloKey struct {
	name  string
	usage uint32
}

func (k *helloKey) open() (ncHandle, ncHandle, error) {
	prov, err := ncOpenProvider(providerPassport)
	if err != nil {
		return 0, 0, err
	}
	ncSetHWND(prov)
	h, err := ncOpenKey(prov, k.name)
	if err != nil {
		ncFree(prov)
		return 0, 0, err
	}
	return prov, h, nil
}

func (k *helloKey) exists() bool {
	prov, h, err := k.open()
	if err != nil {
		return false
	}
	ncFree(h)
	ncFree(prov)
	return true
}

// create makes the key; Windows Hello asks once to approve creation.
func (k *helloKey) create(context string) error {
	if k.exists() {
		return nil
	}
	prov, err := ncOpenProvider(providerPassport)
	if err != nil {
		return err
	}
	defer ncFree(prov)
	ncSetHWND(prov)
	var h ncHandle
	if err := ncCall("NCryptCreatePersistedKey", procCreatePersistedKey, uintptr(prov), uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(utf16p("RSA"))), uintptr(unsafe.Pointer(utf16p(k.name))), 0, 0); err != nil {
		return err
	}
	defer ncFree(h)
	ncSetHWND(h)
	if err := ncSetU32(h, propLength, 2048); err != nil {
		return err
	}
	if err := ncSetU32(h, propKeyUsage, k.usage); err != nil {
		return err
	}
	if err := ncSetU32(h, propNgcCacheType, ngcAuthMandatory); err != nil {
		if err2 := ncSetU32(h, propNgcCacheLegacy, ngcAuthMandatory); err2 != nil {
			return fmt.Errorf("set NGC cache policy: %v / %v", err, err2)
		}
	}
	_ = ncSetString(h, propUseContext, context)
	return ncCall("NCryptFinalizeKey", procFinalizeKey, uintptr(h), 0)
}

func (k *helloKey) prepPrivateOp(h ncHandle, prompt string) error {
	ncSetHWND(h)
	if prompt == "" {
		prompt = "Approve use of your AWS key"
	}
	if err := ncSetString(h, propUseContext, truncate(prompt, 250)); err != nil {
		return err
	}
	// Ask for a fresh gesture every time; never ride a cached Hello unlock.
	return ncSetU32(h, propGestureRequired, 1)
}

func (k *helloKey) publicKey() (*rsa.PublicKey, error) {
	prov, h, err := k.open()
	if err != nil {
		return nil, err
	}
	defer ncFree(prov)
	defer ncFree(h)
	return ncExportRSAPublic(h)
}

// helloSealer: wrap = public RSA op (no prompt), unwrap = Windows Hello.
type helloSealer struct{ k helloKey }

func (s *helloSealer) Name() string { return "windows-hello" }

func (s *helloSealer) Wrap(cek []byte) ([]byte, error) {
	prov, h, err := s.k.open()
	if err != nil {
		return nil, fmt.Errorf("open Windows Hello vault key (run `zsp setup`): %w", err)
	}
	defer ncFree(prov)
	defer ncFree(h)
	return ncCrypt("NCryptEncrypt", procEncrypt, h, cek, nil, bcryptPadPKCS1)
}

func (s *helloSealer) Unwrap(wrapped []byte, prompt string) ([]byte, error) {
	prov, h, err := s.k.open()
	if err != nil {
		return nil, fmt.Errorf("open Windows Hello vault key: %w", err)
	}
	defer ncFree(prov)
	defer ncFree(h)
	if err := s.k.prepPrivateOp(h, prompt); err != nil {
		return nil, err
	}
	return ncCrypt("NCryptDecrypt", procDecrypt, h, wrapped, nil, bcryptPadPKCS1)
}

// helloPinSigner signs account pins with a second Hello key (signing usage).
type helloPinSigner struct{ k helloKey }

type bcryptPKCS1PaddingInfo struct{ algID *uint16 }

func (s *helloPinSigner) Sign(digest []byte, prompt string) ([]byte, error) {
	prov, h, err := s.k.open()
	if err != nil {
		return nil, err
	}
	defer ncFree(prov)
	defer ncFree(h)
	if err := s.k.prepPrivateOp(h, prompt); err != nil {
		return nil, err
	}
	pad := bcryptPKCS1PaddingInfo{algID: utf16p("SHA256")}
	return ncCrypt("NCryptSignHash", procSignHash, h, digest, unsafe.Pointer(&pad), bcryptPadPKCS1)
}

func (s *helloPinSigner) PublicKey() (*rsa.PublicKey, error) { return s.k.publicKey() }

func ncExportRSAPublic(h ncHandle) (*rsa.PublicKey, error) {
	var n uint32
	bt := utf16p(rsaPublicBlobType)
	if err := ncCall("NCryptExportKey", procExportKey, uintptr(h), 0, uintptr(unsafe.Pointer(bt)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if err := ncCall("NCryptExportKey", procExportKey, uintptr(h), 0, uintptr(unsafe.Pointer(bt)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0); err != nil {
		return nil, err
	}
	return parseRSAPublicBlob(buf[:n])
}

// BCRYPT_RSAKEY_BLOB: Magic, BitLength, cbPublicExp, cbModulus, cbPrime1, cbPrime2, then big-endian exp, modulus.
func parseRSAPublicBlob(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 24 || binary.LittleEndian.Uint32(b[0:]) != bcryptRSAPublicMagic {
		return nil, errors.New("unexpected RSA public key blob")
	}
	cbExp := int(binary.LittleEndian.Uint32(b[8:]))
	cbMod := int(binary.LittleEndian.Uint32(b[12:]))
	if len(b) < 24+cbExp+cbMod || cbExp > 8 {
		return nil, errors.New("truncated RSA public key blob")
	}
	e := new(big.Int).SetBytes(b[24 : 24+cbExp]).Int64()
	m := new(big.Int).SetBytes(b[24+cbExp : 24+cbExp+cbMod])
	return &rsa.PublicKey{N: m, E: int(e)}, nil
}

// ---------------------------------------------------------------------------------
// Quiet key: plain TPM 2.0 via the Platform Crypto Provider, DPAPI as fallback.

const quietKeyName = "aws-cli-zsp-quiet-key"

type tpmSealer struct{}

func (tpmSealer) Name() string { return "tpm" }

func tpmOpen() (ncHandle, ncHandle, error) {
	prov, err := ncOpenProvider(providerPlatform)
	if err != nil {
		return 0, 0, err
	}
	h, err := ncOpenKey(prov, quietKeyName)
	if err != nil {
		ncFree(prov)
		return 0, 0, err
	}
	return prov, h, nil
}

func tpmCreate() error {
	if prov, h, err := tpmOpen(); err == nil {
		ncFree(h)
		ncFree(prov)
		return nil
	}
	prov, err := ncOpenProvider(providerPlatform)
	if err != nil {
		return err
	}
	defer ncFree(prov)
	var h ncHandle
	if err := ncCall("NCryptCreatePersistedKey", procCreatePersistedKey, uintptr(prov), uintptr(unsafe.Pointer(&h)),
		uintptr(unsafe.Pointer(utf16p("RSA"))), uintptr(unsafe.Pointer(utf16p(quietKeyName))), 0, 0); err != nil {
		return err
	}
	defer ncFree(h)
	if err := ncSetU32(h, propLength, 2048); err != nil {
		return err
	}
	if err := ncSetU32(h, propKeyUsage, allowDecrypt); err != nil {
		return err
	}
	return ncCall("NCryptFinalizeKey", procFinalizeKey, uintptr(h), 0)
}

func (tpmSealer) Wrap(cek []byte) ([]byte, error) {
	prov, h, err := tpmOpen()
	if err != nil {
		return nil, fmt.Errorf("open TPM quiet key: %w", err)
	}
	defer ncFree(prov)
	defer ncFree(h)
	return ncCrypt("NCryptEncrypt", procEncrypt, h, cek, nil, bcryptPadPKCS1)
}

func (tpmSealer) Unwrap(w []byte, _ string) ([]byte, error) {
	prov, h, err := tpmOpen()
	if err != nil {
		return nil, fmt.Errorf("open TPM quiet key: %w", err)
	}
	defer ncFree(prov)
	defer ncFree(h)
	return ncCrypt("NCryptDecrypt", procDecrypt, h, w, nil, bcryptPadPKCS1|ncryptSilentFlag)
}

// DPAPI fallback (user-scoped, software). Used only when the PC has no usable TPM.
var (
	modCrypt32             = syscall.NewLazyDLL("crypt32.dll")
	procCryptProtectData   = modCrypt32.NewProc("CryptProtectData")
	procCryptUnprotectData = modCrypt32.NewProc("CryptUnprotectData")
	procLocalFree          = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")
)

type dataBlob struct {
	cb uint32
	pb *byte
}

type dpapiSealer struct{}

func (dpapiSealer) Name() string { return "dpapi" }

func dpapiCall(p *syscall.LazyProc, in []byte) ([]byte, error) {
	src := dataBlob{cb: uint32(len(in)), pb: &in[0]}
	var dst dataBlob
	const uiForbidden = 0x1
	r, _, e := p.Call(uintptr(unsafe.Pointer(&src)), 0, 0, 0, 0, uiForbidden, uintptr(unsafe.Pointer(&dst)))
	if r == 0 {
		return nil, fmt.Errorf("DPAPI: %v", e)
	}
	defer procLocalFree.Call(uintptr(unsafe.Pointer(dst.pb)))
	out := make([]byte, dst.cb)
	copy(out, unsafe.Slice(dst.pb, dst.cb))
	return out, nil
}

func (dpapiSealer) Wrap(cek []byte) ([]byte, error) { return dpapiCall(procCryptProtectData, cek) }
func (dpapiSealer) Unwrap(w []byte, _ string) ([]byte, error) {
	return dpapiCall(procCryptUnprotectData, w)
}

// ---------------------------------------------------------------------------------

func deletePassportKey(logical string) error {
	name, err := passportKeyName(logical)
	if err != nil {
		return err
	}
	k := helloKey{name: name}
	prov, h, err := k.open()
	if err != nil {
		return nil
	}
	defer ncFree(prov)
	return ncCall("NCryptDeleteKey", procDeleteKey, uintptr(h), 0) // frees h
}

func deleteTPMKey() error {
	prov, h, err := tpmOpen()
	if err != nil {
		return nil
	}
	defer ncFree(prov)
	return ncCall("NCryptDeleteKey", procDeleteKey, uintptr(h), 0)
}
