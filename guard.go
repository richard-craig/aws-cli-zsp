package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// Config guard (v0.2).
//
// The dangerous edit to ~/.aws/config is not credential_process: it is a line
// that sends your *signed requests* somewhere else. endpoint_url, ca_bundle
// (a TLS man-in-the-middle), a proxy, or the AWS_ENDPOINT_URL family of
// variables all make your own `aws` commands deliver live session tokens to an
// attacker, long after a one-shot malicious install script has exited.
//
// Before any credentials are handed out, zsp compares those settings with a
// baseline you approved. Anything new or changed refuses the request until you
// approve it with Windows Hello (`zsp guard approve`).

// ConfigSnapshot is what the client sees: the config file the AWS CLI will
// read and the relevant environment of the process that asked.
type ConfigSnapshot struct {
	ConfigPath string            `json:"config_path"`
	Config     string            `json:"config"`
	Env        map[string]string `json:"env"`
	Exe        string            `json:"exe"`               // the zsp.exe that the CLI ran
	TrustedExe []string          `json:"trusted,omitempty"` // zsp's own install locations
}

// guardedEnv lists environment variables that redirect or intercept traffic.
func guardedEnvName(k string) bool {
	u := strings.ToUpper(k)
	switch u {
	case "AWS_CA_BUNDLE", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE",
		"AWS_STS_REGIONAL_ENDPOINTS", "AWS_USE_FIPS_ENDPOINT", "AWS_USE_DUALSTACK_ENDPOINT", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
		"NODE_EXTRA_CA_CERTS":
		return true
	}
	return strings.HasPrefix(u, "AWS_ENDPOINT_URL")
}

var guardedConfigKeys = map[string]bool{
	"endpoint_url": true, "ca_bundle": true, "proxy": true, "https_proxy": true, "http_proxy": true,
	"ignore_configured_endpoint_urls": true, "use_fips_endpoint": true, "use_dualstack_endpoint": true,
}

// Keys that make a *vault* profile get credentials from somewhere other than zsp.
var hijackKeys = map[string]bool{
	"role_arn": true, "source_profile": true, "credential_source": true, "web_identity_token_file": true,
	"sso_session": true, "sso_start_url": true, "sso_account_id": true, "sso_role_name": true,
	"aws_access_key_id": true, "aws_secret_access_key": true, "aws_session_token": true,
}

type GuardFinding struct {
	Key   string `json:"key"` // stable id, e.g. "config:[profile prod].endpoint_url"
	Value string `json:"value"`
}

// analyzeConfig lists every security-relevant setting. vaultProfiles are the
// profiles served by zsp; expectedExe is the zsp.exe credential_process must use.
func analyzeConfig(snap *ConfigSnapshot, vaultProfiles []string, expectedExe string) []GuardFinding {
	okExe := func(line string) bool {
		if credentialProcessOK(line, expectedExe) {
			return true
		}
		for _, x := range snap.TrustedExe {
			if credentialProcessOK(line, x) {
				return true
			}
		}
		return false
	}
	var out []GuardFinding
	inVault := map[string]bool{}
	for _, p := range vaultProfiles {
		inVault[p] = true
	}
	if snap == nil {
		return out
	}
	f := parseINI(snap.Config)
	for _, s := range f.sections {
		if s.header == "" {
			continue
		}
		prof, isProfile := profileFromConfigSection(s.name)
		for _, l := range s.lines {
			if l.key == "" {
				continue
			}
			id := "config:[" + s.name + "]." + l.key
			switch {
			case guardedConfigKeys[l.key]:
				out = append(out, GuardFinding{id, l.val})
			case strings.HasPrefix(s.name, "services "):
				// [services x] blocks only exist to redirect endpoints.
				out = append(out, GuardFinding{id, l.val})
			case isProfile && inVault[prof] && hijackKeys[l.key]:
				out = append(out, GuardFinding{id, l.val})
			case isProfile && inVault[prof] && l.key == "credential_process":
				if !okExe(l.val) {
					out = append(out, GuardFinding{id, l.val})
				}
			case isProfile && l.key == "services":
				out = append(out, GuardFinding{id, l.val})
			}
		}
	}
	for k, v := range snap.Env {
		if guardedEnvName(k) && v != "" {
			out = append(out, GuardFinding{"env:" + strings.ToUpper(k), v})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func credentialProcessOK(line, expectedExe string) bool {
	l := strings.ToLower(strings.TrimSpace(line))
	exe := strings.ToLower(expectedExe)
	if exe == "" {
		return strings.Contains(l, "credential-process")
	}
	return (strings.HasPrefix(l, `"`+exe+`"`) || strings.HasPrefix(l, exe+" ")) && strings.Contains(l, " credential-process ")
}

type GuardBaseline struct {
	Approved map[string]string `json:"approved"`
	Updated  time.Time         `json:"updated"`
}

func (e *Engine) guardPath() string { return e.path("guard.sealed") }

func (e *Engine) loadBaseline() (*GuardBaseline, error) {
	env, err := readEnvelope(e.guardPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	pt, err := env.open(e.Quiet, "")
	if err != nil {
		return nil, fmt.Errorf("guard baseline: %w", err)
	}
	var b GuardBaseline
	return &b, json.Unmarshal(pt, &b)
}

func (e *Engine) saveBaseline(b *GuardBaseline) error {
	b.Updated = time.Now().UTC()
	env, err := seal(e.Quiet, kindQuiet, "guard", "", mustJSON(b), nil)
	if err != nil {
		return err
	}
	return writeEnvelope(e.guardPath(), env)
}

// GuardDiff returns findings that are not in the approved baseline.
func (e *Engine) GuardDiff(snap *ConfigSnapshot) ([]GuardFinding, []GuardFinding, error) {
	expected := ""
	if snap != nil {
		expected = snap.Exe
	}
	served := e.profiles()
	for _, p := range e.settings().Profiles {
		if p != nil && p.WriteProfile != "" {
			served = append(served, p.WriteProfile)
		}
	}
	found := analyzeConfig(snap, served, expected)
	base, err := e.loadBaseline()
	if err != nil {
		return found, nil, err
	}
	var unapproved []GuardFinding
	for _, f := range found {
		if base == nil || base.Approved[f.Key] != f.Value {
			unapproved = append(unapproved, f)
		}
	}
	return found, unapproved, nil
}

// guardCheck refuses credentials while unapproved redirections exist.
func (e *Engine) guardCheck(profile string, snap *ConfigSnapshot) error {
	if snap == nil {
		return errors.New("the client sent no config snapshot (old zsp.exe?)")
	}
	found, bad, err := e.GuardDiff(snap)
	if err != nil {
		e.Audit("guard-refused", profile, false, err.Error(), e.Caller.Desc)
		return err
	}
	if len(bad) == 0 {
		base, _ := e.loadBaseline()
		if base == nil { // first use with a clean config: record the empty baseline
			_ = e.saveBaseline(&GuardBaseline{Approved: map[string]string{}})
		}
		_ = found
		return nil
	}
	var lines []string
	for _, f := range bad {
		lines = append(lines, fmt.Sprintf("  %s = %s", f.Key, truncate(f.Value, 120)))
	}
	e.Audit("guard-refused", profile, false, fmt.Sprintf("%d unapproved setting(s): %s", len(bad), bad[0].Key), e.Caller.Desc)
	return fmt.Errorf("REFUSED: your AWS config or environment now redirects or intercepts AWS traffic, and you have not approved it:\n%s\nIf you made this change, approve it with:  zsp guard approve\nIf you did not, remove it and run `zsp revoke --profile %s`", strings.Join(lines, "\n"), profile)
}

// GuardApprove records the current findings as the baseline (Hello-gated).
func (e *Engine) GuardApprove(snap *ConfigSnapshot) error {
	found, bad, err := e.GuardDiff(snap)
	if err != nil && !strings.Contains(err.Error(), "guard baseline") {
		return err
	}
	if len(bad) > 0 {
		var names []string
		for _, f := range bad {
			names = append(names, f.Key+" = "+truncate(f.Value, 60))
		}
		if err := e.approve("", "Approve AWS traffic settings:\n"+truncate(strings.Join(names, "\n"), 220)); err != nil {
			return err
		}
	}
	b := &GuardBaseline{Approved: map[string]string{}}
	for _, f := range found {
		b.Approved[f.Key] = f.Value
	}
	if err := e.saveBaseline(b); err != nil {
		return err
	}
	e.Audit("guard-approved", "", true, fmt.Sprintf("%d setting(s) approved", len(found)), e.Caller.Desc)
	e.printf("Approved %d traffic setting(s).\n", len(found))
	for _, f := range found {
		e.printf("  %s = %s\n", f.Key, truncate(f.Value, 100))
	}
	return nil
}
