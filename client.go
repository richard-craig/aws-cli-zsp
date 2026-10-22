package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Backend runs requests: in-process (user mode) or via the service (service mode).
type Backend interface {
	Do(req *Request) (*Response, error)
	Mode() Mode
}

// consoleUI talks to the person at the terminal. out is stderr for
// credential-process (stdout must carry only the JSON for the AWS CLI).
type consoleUI struct{ out io.Writer }

func (u consoleUI) Printf(format string, a ...any) { fmt.Fprintf(u.out, format, a...) }
func (u consoleUI) Ask(prompt string) (string, error) {
	return consoleAsk(prompt)
}
func (u consoleUI) HelloUnwrap(blob []byte, prompt string) ([]byte, error) {
	return localHelloUnwrap(blob, prompt)
}

// --- user mode -----------------------------------------------------------------------

type localBackend struct {
	e  *Engine
	ui UI
}

func (b *localBackend) Mode() Mode { return ModeUser }

func (b *localBackend) Do(req *Request) (*Response, error) {
	if req.Caller.Desc == "" {
		req.Caller = describeCaller()
	}
	b.e.UI = b.ui
	return dispatch(b.e, req)
}

// --- service mode -------------------------------------------------------------------------

type serviceBackend struct{ ui UI }

func (b *serviceBackend) Mode() Mode { return ModeService }

func (b *serviceBackend) Do(req *Request) (*Response, error) {
	// The broker determines the caller itself; the client contributes idle time.
	req.Caller = CallerInfo{}
	if d, ok := localIdle(); ok {
		req.Caller.Idle, req.Caller.IdleKnown = d, true
	}
	conn, err := dialService()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return clientRoundTrip(conn, req, b.ui)
}

// openBackend picks the mode. If the service is installed, it is always used:
// falling back to user mode when it is down would be a silent downgrade.
func openBackend(ui UI, create bool) (Backend, error) {
	installed, running := serviceState()
	if installed && os.Getenv("ZSP_FORCE_USER_MODE") != "1" {
		if !running {
			return nil, errors.New("the AwsCliZsp service is installed but not running (an administrator can run: sc start AwsCliZsp)")
		}
		return &serviceBackend{ui: ui}, nil
	}
	e, err := openUserEngine(create)
	if err != nil {
		return nil, err
	}
	return &localBackend{e: e, ui: ui}, nil
}

// buildSnapshot captures what the AWS CLI is going to use, for the config guard.
func buildSnapshot() *ConfigSnapshot {
	s := &ConfigSnapshot{ConfigPath: configFile(), Env: map[string]string{}, Exe: cliExePath(), TrustedExe: zspInstallPaths()}
	if b, err := os.ReadFile(s.ConfigPath); err == nil {
		s.Config = string(b)
	}
	for _, kv := range os.Environ() {
		if i := strings.Index(kv, "="); i > 0 && guardedEnvName(kv[:i]) {
			s.Env[strings.ToUpper(kv[:i])] = kv[i+1:]
		}
	}
	return s
}

func statusOf(b Backend) (*StatusData, error) {
	resp, err := b.Do(&Request{Op: "status"})
	if err != nil {
		return nil, err
	}
	var sd StatusData
	if err := jsonUnmarshal(resp.Data, &sd); err != nil {
		return nil, err
	}
	return &sd, nil
}

func waitUntil(d time.Duration, f func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return true
		}
		time.Sleep(250 * time.Millisecond)
	}
	return f()
}

// zspInstallPaths are the places zsp installs itself (user and service mode).
func zspInstallPaths() []string {
	out := []string{filepath.Join(userInstallDir(), "zsp.exe")}
	if pf := os.Getenv("ProgramFiles"); pf != "" {
		out = append(out, filepath.Join(pf, "aws-cli-zsp", "zsp.exe"))
	}
	return out
}
