package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// version_ is set at release time: -ldflags "-X main.version_=1.0.0"
var version_ = "1.0.0-dev"

// userVaultDir is the user-mode vault: %LOCALAPPDATA%\aws-cli-zsp.
// ZSP_HOME overrides it (tests, throwaway vaults).
func userVaultDir() string {
	if d := os.Getenv("ZSP_HOME"); d != "" {
		return d
	}
	if d := os.Getenv("LOCALAPPDATA"); d != "" {
		return filepath.Join(d, "aws-cli-zsp")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aws-cli-zsp")
}

func awsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aws")
}

func credentialsFile() string {
	if f := os.Getenv("AWS_SHARED_CREDENTIALS_FILE"); f != "" {
		return f
	}
	return filepath.Join(awsDir(), "credentials")
}

func configFile() string {
	if f := os.Getenv("AWS_CONFIG_FILE"); f != "" {
		return f
	}
	return filepath.Join(awsDir(), "config")
}

// cliExeOverride, when set, is the zsp.exe that credential_process lines point at.
var cliExeOverride string

// cliExePath is the console binary that credential_process must point at,
// even when the caller is the windowless watcher (zspw.exe).
func cliExePath() string {
	if cliExeOverride != "" {
		return cliExeOverride
	}
	exe, err := os.Executable()
	if err != nil {
		return "zsp.exe"
	}
	name := "zsp"
	if strings.HasSuffix(strings.ToLower(exe), ".exe") {
		name = "zsp.exe"
	}
	return filepath.Join(filepath.Dir(exe), name)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(data)
	serr := tmp.Sync()
	cerr := tmp.Close()
	if werr != nil || serr != nil || cerr != nil {
		os.Remove(name)
		return errors.Join(werr, serr, cerr)
	}
	_ = os.Chmod(name, perm)
	// Windows rename can fail transiently while AV or the indexer holds the target.
	var rerr error
	for i := 0; i < 5; i++ {
		if rerr = os.Rename(name, path); rerr == nil {
			return nil
		}
		time.Sleep(time.Duration(50*(i+1)) * time.Millisecond)
	}
	os.Remove(name)
	return rerr
}

func safeProfileName(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" {
		return "", errors.New("profile name is required")
	}
	if strings.ContainsAny(p, `/\:*?"<>|~`) || p == "." || p == ".." || len(p) > 100 {
		return "", fmt.Errorf("profile name %q is not supported (no / \\ : * ? \" < > | ~, max 100 chars)", p)
	}
	return p, nil
}

func maskKeyID(id string) string {
	if len(id) <= 8 {
		return "****"
	}
	return id[:4] + strings.Repeat("*", len(id)-8) + id[len(id)-4:]
}

func maskAccount(a string) string {
	if len(a) <= 4 {
		return a
	}
	return strings.Repeat("*", len(a)-4) + a[len(a)-4:]
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// acquireLock is a cross-process lock on O_EXCL file creation. Two `aws`
// commands started together must not raise two Windows Hello prompts or
// interleave audit lines. A lock older than 3 minutes is treated as abandoned.
func acquireLock(path string, wait time.Duration) (func(), error) {
	const staleAfter = 3 * time.Minute
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			fmt.Fprintf(f, "%d %d", os.Getpid(), time.Now().Unix())
			f.Close()
			return func() { os.Remove(path) }, nil
		}
		if !errors.Is(err, os.ErrExist) && !errors.Is(err, os.ErrPermission) {
			return nil, err
		}
		if st, serr := os.Stat(path); serr == nil && time.Since(st.ModTime()) > staleAfter {
			os.Remove(path)
			continue
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("timed out waiting for %s", filepath.Base(path))
		}
		time.Sleep(150 * time.Millisecond)
	}
}
