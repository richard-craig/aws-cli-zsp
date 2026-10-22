//go:build !windows

package main

// Non-Windows build: SOFTWARE stand-ins so the engine, broker and protocol can
// be developed and unit-tested on Linux/macOS. No hardware protection; refuses
// to run unless ZSP_INSECURE_DEV=1. The real tool is the Windows build.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type swKey struct{ path string }

func (k swKey) load(create bool) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(k.path)
	if errors.Is(err, os.ErrNotExist) && create {
		pk, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		der := x509.MarshalPKCS1PrivateKey(pk)
		if err := writeFileAtomic(k.path, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		return pk, nil
	}
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("bad dev key")
	}
	return x509.ParsePKCS1PrivateKey(blk.Bytes)
}

// devPrompts records every "Windows Hello" prompt (tests assert on them).
// devDeclineHello makes the next prompts fail, like pressing Cancel.
var devPrompts []string
var devDeclineHello bool

type swSealer struct {
	name   string
	k      swKey
	prompt bool
}

func (s *swSealer) Name() string { return s.name }
func (s *swSealer) Wrap(cek []byte) ([]byte, error) {
	pk, err := s.k.load(false)
	if err != nil {
		return nil, err
	}
	return rsa.EncryptPKCS1v15(rand.Reader, &pk.PublicKey, cek)
}
func (s *swSealer) Unwrap(w []byte, prompt string) ([]byte, error) {
	if s.prompt {
		devPrompts = append(devPrompts, prompt)
		if devDeclineHello {
			return nil, errors.New("cancelled at the Windows Hello prompt")
		}
	}
	pk, err := s.k.load(false)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, pk, w)
}

type swSigner struct{ k swKey }

func (s swSigner) Sign(d []byte, prompt string) ([]byte, error) {
	devPrompts = append(devPrompts, prompt)
	if devDeclineHello {
		return nil, errors.New("cancelled at the Windows Hello prompt")
	}
	pk, err := s.k.load(false)
	if err != nil {
		return nil, err
	}
	return rsa.SignPKCS1v15(rand.Reader, pk, crypto.SHA256, d)
}
func (s swSigner) PublicKey() (*rsa.PublicKey, error) {
	pk, err := s.k.load(false)
	if err != nil {
		return nil, err
	}
	return &pk.PublicKey, nil
}

func devGuard() error {
	if os.Getenv("ZSP_INSECURE_DEV") != "1" {
		return errors.New("this build has no hardware key store; the real tool is the Windows build (set ZSP_INSECURE_DEV=1 for development only)")
	}
	return nil
}

func devKey(name string, create bool) (swKey, error) {
	k := swKey{filepath.Join(userVaultDir(), "dev-"+name+".pem")}
	_, err := k.load(create)
	return k, err
}

func openUserEngine(create bool) (*Engine, error) {
	if err := devGuard(); err != nil {
		return nil, err
	}
	keys := map[string]swKey{}
	for _, n := range []string{"guarded", "quiet", "pin"} {
		k, err := devKey(n, create)
		if err != nil {
			return nil, fmt.Errorf("the vault is not set up yet: run `zsp setup` (%v)", err)
		}
		keys[n] = k
	}
	e := &Engine{Mode: ModeUser, Root: userVaultDir(),
		Guarded: &swSealer{name: "dev-hello", k: keys["guarded"], prompt: true},
		Quiet:   &swSealer{name: "dev-quiet", k: keys["quiet"]},
		Pins:    swSigner{keys["pin"]},
	}
	e.Cache = fileCache{e: e}
	e.Probe = Probe{Locked: func() (bool, bool) { return localLocked(), true }, Idle: localIdle}
	e.shipKick = func() { _ = e.ShipNow() }
	return e, e.ensureDirs()
}

func localHelloUnwrap(blob []byte, prompt string) ([]byte, error) {
	k, err := devKey("guarded", false)
	if err != nil {
		return nil, err
	}
	return (&swSealer{name: "dev-hello", k: k, prompt: true}).Unwrap(blob, prompt)
}

func localHelloPublicKey(create bool) (*rsa.PublicKey, error) {
	if err := devGuard(); err != nil {
		return nil, err
	}
	k, err := devKey("guarded", create)
	if err != nil {
		return nil, err
	}
	pk, err := k.load(false)
	if err != nil {
		return nil, err
	}
	return &pk.PublicKey, nil
}

func deleteHardwareKeys() error { return nil }

func localLocked() bool { return os.Getenv("ZSP_TEST_LOCKED") == "1" }

func localIdle() (time.Duration, bool) {
	if v := os.Getenv("ZSP_TEST_IDLE"); v != "" {
		d, err := time.ParseDuration(v)
		return d, err == nil
	}
	return 0, true
}

func describeCaller() CallerInfo {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", os.Getppid()))
	if err != nil {
		return CallerInfo{Desc: "unknown"}
	}
	args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	img, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getppid()))
	return CallerInfo{Desc: truncate(strings.Join(args, " "), 160), Image: img, Args: args}
}

func consoleAsk(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	var s string
	_, err := fmt.Fscanln(os.Stdin, &s)
	return s, err
}

func consoleAskSecret(prompt string) (string, error) { return consoleAsk(prompt) }

func waitForChange(dir string, timeout time.Duration) bool {
	snap := func() string {
		var b strings.Builder
		es, _ := os.ReadDir(dir)
		for _, e := range es {
			if i, err := e.Info(); err == nil {
				fmt.Fprintf(&b, "%s%d%d;", e.Name(), i.Size(), i.ModTime().UnixNano())
			}
		}
		return b.String()
	}
	start, deadline := snap(), time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		if snap() != start {
			return true
		}
	}
	return false
}

func singleInstance(string) (func(), bool)      { return func() {}, true }
func installAutostart(string, bool) error       { return errors.New("autostart is Windows-only") }
func removeAutostart(bool) error                { return nil }
func autostartInstalled() (string, bool)        { return "", false }
func startWatcher(string) error                 { return errors.New("Windows-only") }
func watcherRunning() bool                      { return false }
func stopWatcher()                              {}
func userEnvKeys() []string                     { return nil }
func notify(msg string)                         { fmt.Fprintln(os.Stderr, msg) }
func eventLogger(bool) func(EventLevel, string) { return nil }
func serviceState() (bool, bool)                { return false, false }
func dialService() (io.ReadWriteCloser, error) {
	return nil, errors.New("service mode is Windows-only")
}
func isElevated() bool       { return false }
func serviceExePath() string { return "" }
func shellProfileFiles() []string {
	h, _ := os.UserHomeDir()
	return []string{h + "/.bashrc", h + "/.zshrc"}
}
func platformHealth() []Check {
	return []Check{{"Hardware key store", false, "development build: software keys only", "use the Windows build"}}
}
func helloCheck() Check {
	return Check{"Windows Hello vault key", false, "development build", "use the Windows build"}
}
func cmdServiceInstall(string) error   { return errors.New("service mode is Windows-only") }
func cmdServiceUninstall(bool) error   { return errors.New("service mode is Windows-only") }
func cmdServiceRun() error             { return errors.New("service mode is Windows-only") }
func cmdServiceResetUser(string) error { return errors.New("service mode is Windows-only") }
