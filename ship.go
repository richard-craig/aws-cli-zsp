package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Off-box audit shipping (v0.2).
//
// New audit entries are written as objects to an S3 bucket with Object Lock in
// COMPLIANCE mode, using a dedicated key whose only permission is s3:PutObject
// under one prefix. Malware that steals that key can add noise, but nothing
// shipped can be changed or deleted, not even by the account root, until the
// retention ends. Each object carries the chain hashes, so gaps and rewrites are
// visible across objects. deploy/audit-bucket.yaml creates the bucket and user.

type shipCreds struct {
	AccessKeyID     string `json:"akid"`
	SecretAccessKey string `json:"secret"`
}

type shipState struct {
	Index    int       `json:"index"`     // entries already shipped
	LastHash string    `json:"last_hash"` // hash of the last shipped entry
	LastShip time.Time `json:"last_ship"`
	LastErr  string    `json:"last_err,omitempty"`
}

var bucketRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
var prefixRe = regexp.MustCompile(`^[A-Za-z0-9._/-]*$`)

func (e *Engine) shipCredsPath() string { return e.path("ship-creds.sealed") }
func (e *Engine) shipStatePath() string { return e.path("ship-state.json") }

func (e *Engine) ShipSetup(bucket, region, prefix, akid, secret string) error {
	if !bucketRe.MatchString(bucket) {
		return errors.New("bucket name must be lowercase letters, digits and dashes (no dots: they break TLS)")
	}
	if region == "" {
		return errors.New("--region is required")
	}
	prefix = strings.Trim(prefix, "/")
	if !prefixRe.MatchString(prefix) {
		return errors.New("prefix may only contain letters, digits, . _ / -")
	}
	if !strings.HasPrefix(akid, "AKIA") || len(secret) < 30 {
		return errors.New("give the shipping user's long-lived access key id and secret")
	}
	if err := e.approve("", fmt.Sprintf("Ship this vault's audit trail to s3://%s/%s", bucket, prefix)); err != nil {
		return err
	}
	c := Creds{AccessKeyID: akid, SecretAccessKey: secret}
	probe := e.shipObjectKey(prefix, "setup-"+time.Now().UTC().Format("20060102T150405Z")+".json")
	body := mustJSON(map[string]any{"event": "ship-setup", "user": e.Label, "host": hostname(), "ts": time.Now().UTC()})
	if err := s3PutObject(c, bucket, region, probe, body, "application/json"); err != nil {
		return fmt.Errorf("test upload failed: %w", err)
	}
	env, err := seal(e.Quiet, kindQuiet, "ship-creds", "", mustJSON(shipCreds{akid, secret}), nil)
	if err != nil {
		return err
	}
	if err := writeEnvelope(e.shipCredsPath(), env); err != nil {
		return err
	}
	st := e.settings()
	st.Ship = &ShipConfig{Bucket: bucket, Region: region, Prefix: prefix, KeyMasked: maskKeyID(akid)}
	if err := e.saveSettings(st); err != nil {
		return err
	}
	e.Audit("ship-setup", "", true, fmt.Sprintf("s3://%s/%s", bucket, prefix), e.Caller.Desc)
	e.printf("Audit shipping is on: s3://%s/%s (test object written).\n", bucket, prefix)
	return e.ShipNow()
}

func (e *Engine) ShipOff() error {
	st := e.settings()
	if st.Ship == nil {
		return errors.New("audit shipping is not on")
	}
	if err := e.approve("", "Turn OFF audit shipping to s3://"+st.Ship.Bucket); err != nil {
		return err
	}
	e.Audit("ship-off", "", true, "s3://"+st.Ship.Bucket, e.Caller.Desc)
	_ = e.ShipNow() // ship the "off" event itself, so turning it off is visible off-box
	st.Ship = nil
	os.Remove(e.shipCredsPath())
	return e.saveSettings(st)
}

func hostname() string {
	h, _ := os.Hostname()
	return strings.ToLower(h)
}

func (e *Engine) shipObjectKey(prefix, name string) string {
	who := sessionNameBad.ReplaceAllString(e.Label, "-")
	if e.Mode == ModeService {
		who = filepath.Base(e.Root) // the user's SID: stable even when the broker ships on its own
	}
	if who == "" {
		who = "user"
	}
	now := time.Now().UTC()
	parts := []string{hostname(), who, now.Format("2006"), now.Format("01"), now.Format("02"), name}
	k := strings.Join(parts, "/")
	if prefix != "" {
		k = prefix + "/" + k
	}
	return k
}

func (e *Engine) loadShipState() shipState {
	var s shipState
	if b, err := os.ReadFile(e.shipStatePath()); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

// ShipNow uploads entries not yet shipped. Safe to call often; it is a no-op
// when shipping is off or nothing is new.
func (e *Engine) ShipNow() error {
	st := e.settings()
	if st.Ship == nil {
		return nil
	}
	unlock, err := e.lock("ship", 20*time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	env, err := readEnvelope(e.shipCredsPath())
	if err != nil {
		return fmt.Errorf("shipping key missing: %w", err)
	}
	pt, err := env.open(e.Quiet, "")
	if err != nil {
		return err
	}
	defer zero(pt)
	var sc shipCreds
	if err := json.Unmarshal(pt, &sc); err != nil {
		return err
	}
	c := Creds{AccessKeyID: sc.AccessKeyID, SecretAccessKey: sc.SecretAccessKey}

	state := e.loadShipState()
	entries, rerr := e.readAudit()
	tampered := ""
	if rerr != nil {
		tampered = rerr.Error()
	} else if err := verifyChain(entries, genesisHash); err != nil {
		tampered = err.Error()
	} else if state.Index > len(entries) || (state.Index > 0 && entries[state.Index-1].Hash != state.LastHash) {
		tampered = fmt.Sprintf("entries already shipped were changed or removed locally (shipped %d, file has %d)", state.Index, len(entries))
	}
	if tampered != "" {
		alert := mustJSON(map[string]any{"event": "tamper-detected", "detail": tampered, "user": e.Label, "host": hostname(), "ts": time.Now().UTC()})
		_ = s3PutObject(c, st.Ship.Bucket, st.Ship.Region, e.shipObjectKey(st.Ship.Prefix, time.Now().UTC().Format("20060102T150405Z")+"-TAMPER.json"), alert, "application/json")
		if e.Event != nil {
			e.Event(EventError, "audit tamper detected: "+tampered)
		}
		if state.Index > len(entries) {
			state.Index = len(entries)
		}
	}
	if state.Index >= len(entries) {
		return nil
	}
	batch := entries[state.Index:]
	var buf bytes.Buffer
	for _, a := range batch {
		buf.Write(mustJSON(a))
		buf.WriteByte('\n')
	}
	last := batch[len(batch)-1]
	name := fmt.Sprintf("%s-%06d-%06d-%s.jsonl", time.Now().UTC().Format("20060102T150405Z"), state.Index+1, state.Index+len(batch), last.Hash[:12])
	if err := s3PutObject(c, st.Ship.Bucket, st.Ship.Region, e.shipObjectKey(st.Ship.Prefix, name), buf.Bytes(), "application/x-ndjson"); err != nil {
		state.LastErr = err.Error()
		b, _ := json.MarshalIndent(state, "", "  ")
		_ = writeFileAtomic(e.shipStatePath(), b, 0o600)
		return err
	}
	state.Index += len(batch)
	state.LastHash = last.Hash
	state.LastShip = time.Now().UTC()
	state.LastErr = ""
	b, _ := json.MarshalIndent(state, "", "  ")
	return writeFileAtomic(e.shipStatePath(), b, 0o600)
}
