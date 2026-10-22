package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// Client-side handling of ~/.aws. The vault (local engine or service) never
// touches the user's files; zsp.exe reads plaintext keys, hands them to the
// vault, and only after the vault confirms the sealed copy is on disk does it
// scrub ~/.aws and wire the profile to credential_process.

type foundKey struct {
	Profile string
	File    string // "credentials" or "config"
	AKID    string
	Secret  string
}

// findPlaintextKeys lists long-lived keys in both AWS files. Profiles that carry
// aws_session_token are temporary credentials and are left alone.
func findPlaintextKeys() ([]foundKey, error) {
	var out []foundKey
	cred, err := readINI(credentialsFile())
	if err != nil {
		return nil, err
	}
	for _, s := range cred.sections {
		if s.header == "" {
			continue
		}
		if k, ok := keyIn(s); ok {
			k.Profile, k.File = s.name, "credentials"
			out = append(out, k)
		}
	}
	cfg, err := readINI(configFile())
	if err != nil {
		return nil, err
	}
	for _, s := range cfg.sections {
		p, ok := profileFromConfigSection(s.name)
		if s.header == "" || !ok {
			continue
		}
		if k, ok := keyIn(s); ok {
			k.Profile, k.File = p, "config"
			out = append(out, k)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Profile < out[j].Profile })
	return out, nil
}

func keyIn(s *iniSection) (foundKey, bool) {
	id, ok1 := s.get("aws_access_key_id")
	sec, ok2 := s.get("aws_secret_access_key")
	_, hasTok := s.get("aws_session_token")
	if !ok1 || !ok2 || id == "" || sec == "" || hasTok {
		return foundKey{}, false
	}
	return foundKey{AKID: id, Secret: sec}, true
}

type importResult struct {
	Moved, Quarantined, Skipped []string
}

// importKeys moves plaintext keys into the vault through the backend.
// only == nil means "every key not on the keep list" (the watcher).
func importKeys(b Backend, only map[string]bool, st Settings, source string) (importResult, error) {
	var res importResult
	found, err := findPlaintextKeys()
	if err != nil || len(found) == 0 {
		return res, err
	}
	done := map[string]bool{}
	for _, k := range found {
		if done[k.Profile] {
			continue // same profile in both files: first wins, both are scrubbed
		}
		name, err := safeProfileName(k.Profile)
		if err != nil {
			res.Skipped = append(res.Skipped, k.Profile+" ("+err.Error()+")")
			continue
		}
		if only != nil && !only[name] {
			continue
		}
		if only == nil && st.isKept(name) {
			continue
		}
		resp, err := b.Do(&Request{Op: "seal", Profile: name, Key: &KeyPayload{AccessKeyID: k.AKID, SecretAccessKey: k.Secret},
			Args: map[string]string{"source": source + " (~/.aws/" + k.File + ")"}})
		if err != nil {
			return res, fmt.Errorf("seal %s: %w", name, err)
		}
		switch resp.Text {
		case "quarantined":
			res.Quarantined = append(res.Quarantined, name)
		default:
			res.Moved = append(res.Moved, name)
		}
		done[name] = true
	}
	if len(done) == 0 {
		return res, nil
	}
	if err := scrubAndWire(done); err != nil {
		return res, fmt.Errorf("keys are sealed, but rewriting ~/.aws failed: %w", err)
	}
	return res, nil
}

// scrubAndWire removes key lines for the given profiles from both files and
// points each profile's credential_process at zsp.
func scrubAndWire(profiles map[string]bool) error {
	cred, err := readINI(credentialsFile())
	if err != nil {
		return err
	}
	for p := range profiles {
		if s := cred.section(p); s != nil {
			s.del("aws_access_key_id", "aws_secret_access_key")
			if s.empty() {
				cred.removeSection(p)
			}
		}
	}
	cfg, err := readINI(configFile())
	if err != nil {
		return err
	}
	for p := range profiles {
		s := cfg.ensureSection(configSectionName(p))
		s.del("aws_access_key_id", "aws_secret_access_key")
		s.set("credential_process", credentialProcessLine(p, ""))
	}
	if err := os.MkdirAll(awsDir(), 0o700); err != nil {
		return err
	}
	// Config first: if the second write fails, the profile is wired to the vault
	// and the stale credentials entry is merely redundant, never lost.
	if err := writeFileAtomic(configFile(), []byte(cfg.String()), 0o600); err != nil {
		return err
	}
	return writeFileAtomic(credentialsFile(), []byte(cred.String()), 0o600)
}

func credentialProcessLine(profile, tier string) string {
	exe := cliExePath()
	q := exe
	if strings.ContainsAny(exe, " \t") {
		q = `"` + exe + `"`
	}
	p := profile
	if strings.ContainsAny(p, " \t") {
		p = `"` + p + `"`
	}
	line := q + " credential-process --profile " + p
	if tier == tierWrite {
		line += " --tier write"
	}
	return line
}

// wireWriteProfile creates [profile <writeProfile>] for the write tier, copying
// the region of the base profile.
func wireWriteProfile(profile, writeProfile string) error {
	cfg, err := readINI(configFile())
	if err != nil {
		return err
	}
	s := cfg.ensureSection(configSectionName(writeProfile))
	s.set("credential_process", credentialProcessLine(profile, tierWrite))
	if base := cfg.section(configSectionName(profile)); base != nil {
		if r, ok := base.get("region"); ok {
			if _, has := s.get("region"); !has {
				s.set("region", r)
			}
		}
	}
	return writeFileAtomic(configFile(), []byte(cfg.String()), 0o600)
}

func unwireProfile(profile string) error {
	cfg, err := readINI(configFile())
	if err != nil {
		return err
	}
	if s := cfg.section(configSectionName(profile)); s != nil {
		s.del("credential_process")
		if s.empty() {
			cfg.removeSection(configSectionName(profile))
		}
	}
	return writeFileAtomic(configFile(), []byte(cfg.String()), 0o600)
}

func removeProfileSection(profile string) error {
	cfg, err := readINI(configFile())
	if err != nil {
		return err
	}
	cfg.removeSection(configSectionName(profile))
	return writeFileAtomic(configFile(), []byte(cfg.String()), 0o600)
}

func writePlaintextKey(profile, akid, secret string) error {
	cred, err := readINI(credentialsFile())
	if err != nil {
		return err
	}
	s := cred.ensureSection(profile)
	s.set("aws_access_key_id", akid)
	s.set("aws_secret_access_key", secret)
	if err := os.MkdirAll(awsDir(), 0o700); err != nil {
		return err
	}
	return writeFileAtomic(credentialsFile(), []byte(cred.String()), 0o600)
}

// wiredProfiles maps profile -> credential_process line for profiles wired to zsp.
func wiredProfiles() map[string]string {
	out := map[string]string{}
	cfg, err := readINI(configFile())
	if err != nil {
		return out
	}
	for _, s := range cfg.sections {
		p, ok := profileFromConfigSection(s.name)
		if !ok {
			continue
		}
		if cp, ok := s.get("credential_process"); ok && strings.Contains(cp, "credential-process") {
			out[p] = cp
		}
	}
	return out
}

// repairWiring puts back credential_process lines for vault profiles (and write
// profiles) that were changed or removed. Returns what it fixed.
func repairWiring(st *StatusData) ([]string, error) {
	cfg, err := readINI(configFile())
	if err != nil {
		return nil, err
	}
	var fixed []string
	want := map[string]string{}
	for _, p := range st.Profiles {
		want[p.Name] = credentialProcessLine(p.Name, "")
		if p.Policy.WriteProfile != "" && p.Policy.WriteRole != "" {
			want[p.Policy.WriteProfile] = credentialProcessLine(p.Name, tierWrite)
		}
	}
	for prof, line := range want {
		s := cfg.ensureSection(configSectionName(prof))
		if cur, _ := s.get("credential_process"); cur != line {
			s.set("credential_process", line)
			fixed = append(fixed, prof)
		}
	}
	if len(fixed) == 0 {
		return nil, nil
	}
	sort.Strings(fixed)
	return fixed, writeFileAtomic(configFile(), []byte(cfg.String()), 0o600)
}
