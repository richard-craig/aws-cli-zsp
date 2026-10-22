package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// CallerInfo describes the program that asked for credentials: the parent of
// zsp.exe (aws.exe, terraform.exe, python.exe, ...). In service mode the broker
// computes it itself from the pipe client's process; the client cannot lie
// about it (only about idle time, which is advisory).
type CallerInfo struct {
	Desc      string        `json:"desc"`            // "aws s3 ls ← pwsh"
	Image     string        `json:"image,omitempty"` // full path of the program
	Args      []string      `json:"args,omitempty"`  // its argv (argv[0] included)
	Signed    bool          `json:"signed,omitempty"`
	Hash      string        `json:"hash,omitempty"` // sha256 of the image when unsigned
	OSSession uint32        `json:"os_session,omitempty"`
	Idle      time.Duration `json:"idle,omitempty"`
	IdleKnown bool          `json:"idle_known,omitempty"`
}

var interpreters = map[string]bool{
	"python": true, "python3": true, "pythonw": true, "py": true, "node": true, "deno": true, "bun": true,
	"pwsh": true, "powershell": true, "powershell_ise": true, "ruby": true, "perl": true, "cmd": true,
	"bash": true, "sh": true, "wsl": true, "java": true, "javaw": true, "dotnet": true, "cscript": true, "wscript": true,
}

// inlineFlags make an interpreter run code given on the command line.
var inlineFlags = map[string]bool{
	"-c": true, "-e": true, "--eval": true, "-p": true, "--print": true, "-command": true,
	"-encodedcommand": true, "-enc": true, "-ec": true, "/c": true, "/k": true, "-r": true,
}

// identity is how a caller is remembered. For a signed program it is its path
// (updates in place keep it trusted); unsigned programs also pin the file hash.
// For interpreters the script is part of the identity, and inline code
// (`python -c ...`, `pwsh -Command ...`) is never remembered.
func (c CallerInfo) identity() (id string, alwaysAsk bool, why string) {
	img := strings.ToLower(c.Image)
	if img == "" {
		return "", true, "the program that asked could not be identified"
	}
	id = img
	if !c.Signed {
		id += "#" + c.Hash
	}
	base := strings.TrimSuffix(baseName(img), ".exe")
	if interpreters[base] {
		script := ""
		for _, a := range c.Args[min(1, len(c.Args)):] {
			la := strings.ToLower(a)
			if inlineFlags[la] {
				return "", true, base + " running inline code"
			}
			if strings.HasPrefix(la, "-") || strings.HasPrefix(la, "/") && len(la) <= 3 {
				continue
			}
			script = la
			break
		}
		if script == "" {
			return "", true, "an interactive " + base + " session"
		}
		id += "|" + script
	}
	return id, false, ""
}

// sensitiveCommand reports whether the caller's command line contains one of
// the configured credential-minting commands, e.g. `aws configure export-credentials`.
func (c CallerInfo) sensitiveCommand(patterns []string) string {
	var words []string
	for _, a := range c.Args[min(1, len(c.Args)):] {
		if !strings.HasPrefix(a, "-") {
			words = append(words, strings.ToLower(a))
		}
	}
	line := " " + strings.Join(words, " ") + " "
	for _, p := range patterns {
		if strings.Contains(line, " "+strings.ToLower(strings.TrimSpace(p))+" ") {
			return p
		}
	}
	return ""
}

// Known callers (service mode) -----------------------------------------------------------

type knownCaller struct {
	Image string    `json:"image"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
}

var knownMu sync.Mutex

func (e *Engine) knownCallersPath() string { return e.path("callers.json") }

func (e *Engine) loadKnownCallers() map[string]*knownCaller {
	m := map[string]*knownCaller{}
	if b, err := os.ReadFile(e.knownCallersPath()); err == nil {
		_ = json.Unmarshal(b, &m)
	}
	return m
}

func callerKey(profile, id string) string { return profile + "|" + id }

func (e *Engine) callerKnown(profile, id string) bool {
	knownMu.Lock()
	defer knownMu.Unlock()
	_, ok := e.loadKnownCallers()[callerKey(profile, id)]
	return ok
}

func (e *Engine) rememberCaller(profile, id, image string) {
	knownMu.Lock()
	defer knownMu.Unlock()
	m := e.loadKnownCallers()
	k := callerKey(profile, id)
	if kc := m[k]; kc != nil {
		kc.Last = time.Now().UTC()
	} else {
		m[k] = &knownCaller{Image: image, First: time.Now().UTC(), Last: time.Now().UTC()}
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = writeFileAtomic(e.knownCallersPath(), b, 0o600)
}

func (e *Engine) forgetCallers(profile string) int {
	knownMu.Lock()
	defer knownMu.Unlock()
	m := e.loadKnownCallers()
	n := 0
	for k := range m {
		if profile == "" || strings.HasPrefix(k, profile+"|") {
			delete(m, k)
			n++
		}
	}
	b, _ := json.MarshalIndent(m, "", "  ")
	_ = writeFileAtomic(e.knownCallersPath(), b, 0o600)
	return n
}

// redaction for anything that leaves the vault (audit details, exports).
var (
	acctRe   = regexp.MustCompile(`\b(\d{8})(\d{4})\b`)
	akidRe   = regexp.MustCompile(`\b(A[SK]IA)[A-Z0-9]{12}([A-Z0-9]{4})\b`)
	secretRe = regexp.MustCompile(`(?i)(secret[_ ]?access[_ ]?key|session[_ ]?token|aws_secret_access_key)\s*[=:]\s*\S+`)
)

func redact(s string) string {
	s = secretRe.ReplaceAllString(s, "$1=<redacted>")
	s = acctRe.ReplaceAllString(s, "********$2")
	return akidRe.ReplaceAllString(s, "$1************$2")
}

// baseName handles both separators, so Windows paths parse the same everywhere.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
