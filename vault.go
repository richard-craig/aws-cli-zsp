package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// KeyPayload is what the guarded envelope protects.
type KeyPayload struct {
	AccessKeyID     string `json:"akid"`
	SecretAccessKey string `json:"secret"`
	UserName        string `json:"user_name,omitempty"`

	// MFAMode: "" (none), "pc" (this PC is the MFA device; seed below) or
	// "phone" (every new session needs a code from the phone, v0.2).
	MFAMode     string `json:"mfa_mode,omitempty"`
	MFASerial   string `json:"mfa_serial,omitempty"`   // virtual device "on this PC"
	MFASeed     string `json:"mfa_seed,omitempty"`     // base32 TOTP seed, never leaves the envelope
	PhoneSerial string `json:"phone_serial,omitempty"` // virtual device on the phone
}

func (k *KeyPayload) wipe() {
	if k == nil {
		return
	}
	k.SecretAccessKey = ""
	k.MFASeed = ""
}

func (k *KeyPayload) mode() string {
	if k.MFAMode != "" {
		return k.MFAMode
	}
	if k.MFASeed != "" { // v0.1 vaults
		return "pc"
	}
	return ""
}

// akidFingerprint identifies a key id exactly without storing it in clear text
// (masked ids collide whenever two keys share their first and last four characters).
func akidFingerprint(akid string) string {
	h := sha256.Sum256([]byte("aws-cli-zsp-akid\n" + akid))
	return fmt.Sprintf("%x", h[:12])
}

func (e *Engine) keyPath(p string) string      { return e.path("keys", p+".sealed") }
func (e *Engine) incomingPath(p string) string { return e.path("keys", p+".incoming.sealed") }
func (e *Engine) pinPath(p string) string      { return e.path("pins", p+".json") }
func (e *Engine) phonePath(p string) string    { return e.path("phone", p+".sealed") }

var errNotInVault = errors.New("profile is not in the vault")
var errNotEnrolled = errors.New("this user is not enrolled with the zsp service yet: run `zsp setup`")

func keyMeta(k *KeyPayload, prev map[string]string) map[string]string {
	m := map[string]string{"akid_masked": maskKeyID(k.AccessKeyID), "akid_id": akidFingerprint(k.AccessKeyID)}
	if k.UserName != "" {
		m["user_name"] = k.UserName
	}
	if mode := k.mode(); mode != "" {
		m["mfa"] = mode
	}
	for _, carry := range []string{"enforced", "phone", "readonly", "netbind"} {
		if v, ok := prev[carry]; ok {
			m[carry] = v
		}
	}
	return m
}

// SealKey stores a key. Public-key only: never prompts.
func (e *Engine) SealKey(profile string, k *KeyPayload, meta map[string]string) error {
	if e.Guarded == nil {
		return errNotEnrolled
	}
	if err := e.ensureDirs(); err != nil {
		return err
	}
	pt, _ := json.Marshal(k)
	defer zero(pt)
	env, err := seal(e.Guarded, kindGuarded, "key", profile, pt, meta)
	if err != nil {
		return err
	}
	return writeEnvelope(e.keyPath(profile), env)
}

func (e *Engine) KeyEnvelope(profile string) (*Envelope, error) {
	env, err := readEnvelope(e.keyPath(profile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", errNotInVault, profile)
	}
	return env, err
}

// OpenKey needs Windows Hello. prompt is shown in the Hello dialog.
func (e *Engine) OpenKey(profile, prompt string) (*KeyPayload, *Envelope, error) {
	if e.Guarded == nil {
		return nil, nil, errNotEnrolled
	}
	env, err := e.KeyEnvelope(profile)
	if err != nil {
		return nil, nil, err
	}
	if env.Kind != kindGuarded || env.Purpose != "key" || env.Profile != profile {
		return nil, nil, errors.New("sealed key file has unexpected type")
	}
	pt, err := env.open(e.Guarded, prompt)
	if err != nil {
		return nil, nil, err
	}
	defer zero(pt)
	var k KeyPayload
	if err := json.Unmarshal(pt, &k); err != nil {
		return nil, nil, err
	}
	return &k, env, nil
}

func (e *Engine) reseal(profile string, key *KeyPayload, prev map[string]string, set map[string]string) error {
	meta := keyMeta(key, prev)
	for k, v := range set {
		if v == "" {
			delete(meta, k)
		} else {
			meta[k] = v
		}
	}
	return e.SealKey(profile, key, meta)
}

func (e *Engine) updateMeta(profile string, set map[string]string) error {
	env, err := readEnvelope(e.keyPath(profile))
	if err != nil {
		return err
	}
	if env.Meta == nil {
		env.Meta = map[string]string{}
	}
	for k, v := range set {
		if v == "" {
			delete(env.Meta, k)
		} else {
			env.Meta[k] = v
		}
	}
	return writeEnvelope(e.keyPath(profile), env)
}

func (e *Engine) profiles() []string {
	entries, _ := os.ReadDir(e.path("keys"))
	var out []string
	for _, d := range entries {
		n := d.Name()
		if strings.HasSuffix(n, ".sealed") && !strings.HasSuffix(n, ".incoming.sealed") {
			out = append(out, strings.TrimSuffix(n, ".sealed"))
		}
	}
	sort.Strings(out)
	return out
}

func (e *Engine) clearSessions(profile string) int {
	if e.Cache == nil {
		return 0
	}
	return e.Cache.Remove(profile, anySession)
}

// approve proves a person is present by opening a vault key with Windows Hello.
// Used to gate settings changes, guard approvals and new callers.
func (e *Engine) approve(profile, reason string) error {
	if profile == "" {
		ps := e.profiles()
		if len(ps) == 0 {
			return nil // empty vault: nothing to protect yet
		}
		profile = ps[0]
	}
	k, _, err := e.OpenKey(profile, reason)
	if err != nil {
		return err
	}
	k.wipe()
	return nil
}

// Import ----------------------------------------------------------------------------

// ImportKey moves a plaintext key into the vault. It never prompts.
// Returns "moved", "replaced", "unchanged" or "quarantined".
func (e *Engine) ImportKey(profile string, in *KeyPayload, source string) (string, error) {
	name, err := safeProfileName(profile)
	if err != nil {
		return "", err
	}
	if e.Guarded == nil {
		return "", errNotEnrolled
	}
	unlock, err := e.lock("import-"+name, 30*time.Second)
	if err != nil {
		return "", err
	}
	defer unlock()
	payload := &KeyPayload{AccessKeyID: in.AccessKeyID, SecretAccessKey: in.SecretAccessKey}
	defer payload.wipe()

	prev, perr := e.KeyEnvelope(name)
	switch {
	case perr == nil && prev.Meta["mfa"] != "":
		if prev.Meta["akid_id"] == akidFingerprint(in.AccessKeyID) {
			e.Audit("key-duplicate", name, true, "same key written again; plaintext copy removed", source)
			return "unchanged", nil
		}
		// The sealed key carries MFA settings that cannot be read without Windows
		// Hello. Don't overwrite: quarantine until the user runs `zsp adopt`.
		env, err := seal(e.Guarded, kindGuarded, "incoming", name, mustJSON(payload), map[string]string{"akid_masked": maskKeyID(in.AccessKeyID), "akid_id": akidFingerprint(in.AccessKeyID)})
		if err == nil {
			err = writeEnvelope(e.incomingPath(name), env)
		}
		if err != nil {
			return "", fmt.Errorf("seal %s: %w", name, err)
		}
		e.Audit("key-quarantined", name, false, "new key "+maskKeyID(in.AccessKeyID)+" written over an MFA-protected profile; run `zsp adopt`", source)
		return "quarantined", nil
	default:
		var meta map[string]string
		if perr == nil {
			meta = prev.Meta
			if prev.Meta["akid_id"] == akidFingerprint(in.AccessKeyID) {
				e.Audit("key-duplicate", name, true, "same key written again; plaintext copy removed", source)
				return "unchanged", nil
			}
			e.clearSessions(name)
		}
		if err := e.SealKey(name, payload, keyMeta(payload, meta)); err != nil {
			return "", fmt.Errorf("seal %s: %w", name, err)
		}
		ev, res := "key-moved", "moved"
		if perr == nil {
			ev, res = "key-replaced", "replaced"
		}
		e.Audit(ev, name, true, maskKeyID(in.AccessKeyID)+" from "+source, source)
		return res, nil
	}
}

// MigrationBundle carries a fully opened user-mode profile into the service.
type MigrationBundle struct {
	Key   *KeyPayload       `json:"key"`
	Meta  map[string]string `json:"meta"`
	Phone *PhoneCopy        `json:"phone,omitempty"`
	Pin   *Pin              `json:"pin,omitempty"`
	Pol   *ProfilePolicy    `json:"policy,omitempty"`
}

func (e *Engine) ImportBundle(profile string, b *MigrationBundle) error {
	name, err := safeProfileName(profile)
	if err != nil {
		return err
	}
	if b.Key == nil || b.Key.AccessKeyID == "" {
		return errors.New("bundle has no key")
	}
	if _, err := e.KeyEnvelope(name); err == nil {
		return fmt.Errorf("%s is already in the service vault", name)
	}
	if err := e.SealKey(name, b.Key, keyMeta(b.Key, b.Meta)); err != nil {
		return err
	}
	if b.Phone != nil {
		if err := e.savePhoneCopy(name, b.Phone); err != nil {
			return err
		}
	}
	if b.Pin != nil {
		if _, err := e.writePin(name, b.Pin.Account, b.Pin.Arn, ""); err != nil {
			return err
		}
	}
	if b.Pol != nil {
		st := e.settings()
		*st.policyFor(name) = *b.Pol
		if err := e.saveSettings(st); err != nil {
			return err
		}
	}
	b.Key.wipe()
	e.Audit("key-migrated", name, true, maskKeyID(b.Key.AccessKeyID)+" from user-mode vault", e.Caller.Desc)
	return nil
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// Phone copy ------------------------------------------------------------------------
//
// The quiet-sealed copy of a key used for phone approval when nobody is at the
// PC. It holds NO MFA seed: AWS only honours it together with a code from the
// phone, and zsp refuses to create it until AWS requires MFA for the key.

type PhoneCopy struct {
	AccessKeyID     string `json:"akid"`
	SecretAccessKey string `json:"secret"`
	PhoneSerial     string `json:"phone_serial"`
}

func (e *Engine) savePhoneCopy(profile string, pc *PhoneCopy) error {
	env, err := seal(e.Quiet, kindQuiet, "phone", profile, mustJSON(pc), map[string]string{"serial": pc.PhoneSerial})
	if err != nil {
		return err
	}
	return writeEnvelope(e.phonePath(profile), env)
}

func (e *Engine) loadPhoneCopy(profile string) (*PhoneCopy, error) {
	env, err := readEnvelope(e.phonePath(profile))
	if err != nil {
		return nil, err
	}
	pt, err := env.open(e.Quiet, "")
	if err != nil {
		return nil, err
	}
	defer zero(pt)
	var pc PhoneCopy
	return &pc, json.Unmarshal(pt, &pc)
}

func (e *Engine) hasPhoneCopy(profile string) bool {
	_, err := os.Stat(e.phonePath(profile))
	return err == nil
}

// Account pin -------------------------------------------------------------------------
//
// The first session for a profile records which AWS account and IAM user the
// key belongs to. Sealing needs only a public key, so without this, malware
// could seal ITS key under your profile name and your next `aws s3 cp` would
// land in the attacker's bucket. User mode: the pin is signed by a second
// Windows Hello key. Service mode: it lives in the ACL-protected vault.

type Pin struct {
	Profile string    `json:"profile"`
	Account string    `json:"account"`
	Arn     string    `json:"arn"`
	Created time.Time `json:"created"`
	Sig     string    `json:"sig,omitempty"`
}

func pinDigest(profile, account, arn string) []byte {
	h := sha256.Sum256([]byte("aws-cli-zsp-pin-v1\n" + profile + "\n" + account + "\n" + arn))
	return h[:]
}

func (e *Engine) writePin(profile, account, arn, prompt string) (*Pin, error) {
	p := &Pin{Profile: profile, Account: account, Arn: arn, Created: time.Now().UTC()}
	if e.Pins != nil {
		sig, err := e.Pins.Sign(pinDigest(profile, account, arn), prompt)
		if err != nil {
			return nil, err
		}
		p.Sig = base64.StdEncoding.EncodeToString(sig)
	}
	b, _ := json.MarshalIndent(p, "", "  ")
	return p, writeFileAtomic(e.pinPath(profile), b, 0o600)
}

func (e *Engine) CreatePin(profile, account, arn string) (*Pin, error) {
	prompt := fmt.Sprintf("Pin AWS profile '%s' to account %s (%s). Approve only if this is your account.", profile, account, shortArn(arn))
	return e.writePin(profile, account, arn, prompt)
}

// LoadPin returns (nil, nil) when no pin exists yet, and an error when a pin
// exists but does not verify.
func (e *Engine) LoadPin(profile string) (*Pin, error) {
	b, err := os.ReadFile(e.pinPath(profile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p Pin
	if err := json.Unmarshal(b, &p); err != nil || p.Profile != profile {
		return nil, errors.New("pin file is corrupt")
	}
	if e.Pins == nil {
		return &p, nil
	}
	sig, err := base64.StdEncoding.DecodeString(p.Sig)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("pin file is not signed")
	}
	pub, err := e.Pins.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("read pin key: %w", err)
	}
	if err := verifyPKCS1SHA256(pub, pinDigest(p.Profile, p.Account, p.Arn), sig); err != nil {
		return nil, errors.New("pin signature does not verify: the pin file was altered")
	}
	return &p, nil
}

func shortArn(arn string) string {
	if i := strings.Index(arn, ":user/"); i >= 0 {
		return "user/" + arn[i+6:]
	}
	if i := strings.LastIndex(arn, ":"); i >= 0 {
		return arn[i+1:]
	}
	return arn
}
