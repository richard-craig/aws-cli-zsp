package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Mode is where the vault lives and who enforces policy.
type Mode string

const (
	// ModeUser: the vault is in %LOCALAPPDATA%, the engine runs inside zsp.exe
	// as the signed-in user. No admin rights needed.
	ModeUser Mode = "user"
	// ModeService: the vault is in %ProgramData%, the engine runs inside the
	// AwsCliZsp Windows service under its own account. zsp.exe is a thin client.
	ModeService Mode = "service"
)

// UI is how the engine reaches the person at the keyboard. In user mode it is
// the console; in service mode it is a remote proxy over the named pipe.
type UI interface {
	Printf(format string, a ...any)
	// Ask reads one line (e.g. a 6-digit MFA code).
	Ask(prompt string) (string, error)
	// HelloUnwrap asks the user's own process to decrypt blob with the user's
	// Windows Hello key, showing prompt. Only used in service mode.
	HelloUnwrap(blob []byte, prompt string) ([]byte, error)
}

// Probe reports whether a person is at the PC. Locked comes from an
// authoritative source (local desktop in user mode, WTS in service mode).
type Probe struct {
	Locked func() (locked bool, known bool)
	Idle   func() (idle time.Duration, known bool)
}

type EventLevel int

const (
	EventInfo EventLevel = iota
	EventWarning
	EventError
)

// Engine holds everything one user's vault needs for one request.
type Engine struct {
	Mode    Mode
	Root    string
	Guarded Sealer    // Windows Hello (user mode) or split Hello+broker (service mode); nil = not enrolled
	Quiet   Sealer    // TPM/DPAPI, never prompts
	Pins    PinSigner // user mode: account pins are signed with a 2nd Hello key; nil in service mode (ACL-protected)
	Cache   SessionCache
	UI      UI
	Caller  CallerInfo
	Probe   Probe
	Event   func(level EventLevel, msg string)
	Label   string // who this vault belongs to (service mode audit)

	// shipNow, when set, is called after a refusal so the audit reaches S3 promptly.
	shipKick func()
}

func (e *Engine) path(parts ...string) string {
	return filepath.Join(append([]string{e.Root}, parts...)...)
}

func (e *Engine) ensureDirs() error {
	for _, d := range []string{"", "keys", "pins", "phone", "locks", "sessions"} {
		if err := os.MkdirAll(e.path(d), 0o700); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) lock(name string, wait time.Duration) (func(), error) {
	return acquireLock(e.path("locks", name+".lock"), wait)
}

func (e *Engine) printf(format string, a ...any) {
	if e.UI != nil {
		e.UI.Printf(format, a...)
	}
}

func (e *Engine) ask(prompt string) (string, error) {
	if e.UI == nil {
		return "", fmt.Errorf("no interactive user to ask: %s", prompt)
	}
	return e.UI.Ask(prompt)
}

// presence answers "is somebody at this PC right now?" for a given idle limit.
func (e *Engine) presence(idleLimit time.Duration) (bool, string) {
	if e.Mode == ModeUser && os.Getenv("ZSP_ASSUME_PRESENT") == "1" {
		return true, ""
	}
	if e.Probe.Locked != nil {
		if locked, known := e.Probe.Locked(); known && locked {
			return false, "the screen is locked"
		}
	}
	if idleLimit > 0 && e.Probe.Idle != nil {
		if idle, known := e.Probe.Idle(); known && idle > idleLimit {
			return false, fmt.Sprintf("no keyboard or mouse input for %d minutes", int(idle.Minutes()))
		}
	}
	return true, ""
}

func (e *Engine) locked() bool {
	if e.Probe.Locked == nil {
		return false
	}
	l, known := e.Probe.Locked()
	return known && l
}
