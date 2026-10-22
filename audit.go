package main

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Hash-chained audit trail.
//
// Every line carries the hash of the line before it, and the newest hash is
// sealed with the quiet key in anchor.sealed, so editing, deleting or
// truncating lines fails `zsp audit verify`. Every entry is also written to the
// Windows Event Log, and can be shipped to an S3 bucket with Object Lock
// (ship.go): copies that malware running as you cannot rewrite.

type AuditEntry struct {
	TS      time.Time `json:"ts"`
	Event   string    `json:"event"`
	Profile string    `json:"profile,omitempty"`
	OK      bool      `json:"ok"`
	Detail  string    `json:"detail,omitempty"`
	Caller  string    `json:"caller,omitempty"`
	User    string    `json:"user,omitempty"`
	Prev    string    `json:"prev"`
	Hash    string    `json:"hash"`
}

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

func (e *Engine) auditPath() string  { return e.path("audit.jsonl") }
func (e *Engine) anchorPath() string { return e.path("anchor.sealed") }

func entryHash(a AuditEntry) string {
	a.Hash = ""
	b, _ := json.Marshal(a)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// Audit appends one entry. It never fails the caller.
func (e *Engine) Audit(event, profile string, ok bool, detail, caller string) {
	err := e.audit(event, profile, ok, detail, caller)
	if err != nil {
		fmt.Fprintf(os.Stderr, "aws-cli-zsp: audit write failed: %v\n", err)
	}
	if e.Event != nil {
		lvl := EventInfo
		if !ok {
			lvl = EventWarning
		}
		if strings.HasPrefix(event, "tamper") || event == "pin-mismatch" || event == "guard-refused" {
			lvl = EventError
		}
		msg := fmt.Sprintf("%s profile=%s ok=%v %s", event, profile, ok, detail)
		if caller != "" {
			msg += " caller=" + caller
		}
		if e.Label != "" {
			msg += " user=" + e.Label
		}
		e.Event(lvl, msg)
	}
	if !ok && e.shipKick != nil {
		e.shipKick()
	}
}

func (e *Engine) audit(event, profile string, ok bool, detail, caller string) error {
	if err := e.ensureDirs(); err != nil {
		return err
	}
	unlock, err := e.lock("audit", 10*time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	prev, _, err := e.lastAuditHash()
	if err != nil {
		return err
	}
	a := AuditEntry{TS: time.Now().UTC(), Event: event, Profile: profile, OK: ok, Detail: redact(detail), Caller: caller, User: e.Label, Prev: prev}
	a.Hash = entryHash(a)
	line, _ := json.Marshal(a)
	f, err := os.OpenFile(e.auditPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if e.Quiet == nil {
		return nil
	}
	env, err := seal(e.Quiet, kindQuiet, "audit-anchor", "", []byte(a.Hash), nil)
	if err != nil {
		return err
	}
	return writeEnvelope(e.anchorPath(), env)
}

func (e *Engine) lastAuditHash() (string, int, error) {
	f, err := os.Open(e.auditPath())
	if errors.Is(err, os.ErrNotExist) {
		return genesisHash, 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	last, n := genesisHash, 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var a AuditEntry
		if json.Unmarshal(line, &a) == nil {
			last = a.Hash
			n++
		}
	}
	return last, n, sc.Err()
}

func (e *Engine) readAudit() ([]AuditEntry, error) {
	b, err := os.ReadFile(e.auditPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []AuditEntry
	for i, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var a AuditEntry
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return out, fmt.Errorf("line %d is not valid JSON", i+1)
		}
		out = append(out, a)
	}
	return out, nil
}

// VerifyAudit walks the chain and compares its head to the sealed anchor.
func (e *Engine) VerifyAudit() (int, error) {
	entries, err := e.readAudit()
	if err != nil {
		return 0, err
	}
	if err := verifyChain(entries, genesisHash); err != nil {
		return 0, err
	}
	prev := genesisHash
	if len(entries) > 0 {
		prev = entries[len(entries)-1].Hash
	}
	env, err := readEnvelope(e.anchorPath())
	if errors.Is(err, os.ErrNotExist) {
		if len(entries) == 0 {
			return 0, nil
		}
		return len(entries), errors.New("the sealed anchor is missing")
	}
	if err != nil {
		return len(entries), err
	}
	head, err := env.open(e.Quiet, "")
	if err != nil {
		return len(entries), fmt.Errorf("open anchor: %w", err)
	}
	if string(head) != prev {
		return len(entries), errors.New("the newest entries were removed (file is shorter than the sealed anchor says)")
	}
	return len(entries), nil
}

func verifyChain(entries []AuditEntry, start string) error {
	prev := start
	for i, a := range entries {
		if a.Prev != prev {
			return fmt.Errorf("entry %d does not follow entry %d (a line was removed or reordered)", i+1, i)
		}
		if entryHash(a) != a.Hash {
			return fmt.Errorf("entry %d was edited after it was written", i+1)
		}
		prev = a.Hash
	}
	return nil
}

func verifyPKCS1SHA256(pub *rsa.PublicKey, digest, sig []byte) error {
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, sig)
}
