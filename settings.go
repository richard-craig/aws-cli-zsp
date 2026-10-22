package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ProfilePolicy is per-profile behaviour.
type ProfilePolicy struct {
	Duration      string `json:"duration,omitempty"`       // read/base session length
	ReadRole      string `json:"read_role,omitempty"`      // v0.3 tiered access
	WriteRole     string `json:"write_role,omitempty"`     //
	WriteProfile  string `json:"write_profile,omitempty"`  // AWS profile wired to the write tier
	WriteDuration string `json:"write_duration,omitempty"` // default 15m, max 1h
}

// ShipConfig is the non-secret half of the S3 audit shipping config. The
// shipping key itself is sealed in ship-creds.sealed.
type ShipConfig struct {
	Bucket    string `json:"bucket"`
	Region    string `json:"region"`
	Prefix    string `json:"prefix"`
	KeyMasked string `json:"key_masked"`
}

type Settings struct {
	AutoMove        bool              `json:"auto_move"`
	Keep            []string          `json:"keep"`
	DefaultDuration string            `json:"default_duration"`
	Durations       map[string]string `json:"durations,omitempty"` // v0.1 layout, migrated into Profiles

	// Presence. IdleMinutes gates new sessions; ReuseIdleMinutes gates handing
	// out a cached one (v0.2).
	IdleMinutes        int    `json:"idle_minutes"`
	ReuseIdleMinutes   int    `json:"reuse_idle_minutes"`
	ReusePresence      string `json:"reuse_presence"`        // "lock+idle" (default), "lock", "off"
	KeepSessionsOnLock bool   `json:"keep_sessions_on_lock"` // default false: lock clears Hello sessions

	// Caller approval (enforced in service mode).
	NewCallerApproval string   `json:"new_caller_approval"` // "on" (default) or "off"
	SensitiveCommands []string `json:"sensitive_commands,omitempty"`

	QuietBackend string                    `json:"quiet_backend,omitempty"` // user mode: "tpm" or "dpapi"
	Profiles     map[string]*ProfilePolicy `json:"profiles,omitempty"`
	Ship         *ShipConfig               `json:"ship,omitempty"`
}

// Commands that print or mint credentials. A cached session is never handed to
// these without a fresh Windows Hello approval.
var defaultSensitiveCommands = []string{
	"configure export-credentials",
	"sts assume-role",
	"sts assume-role-with-saml",
	"sts assume-role-with-web-identity",
	"sts get-federation-token",
	"sts get-session-token",
	"iam create-access-key",
	"ecr get-login-password",
	"ecr get-authorization-token",
	"codeartifact get-authorization-token",
	"sso get-role-credentials",
}

func defaultSettings() Settings {
	return Settings{
		AutoMove: true, DefaultDuration: "1h", IdleMinutes: 5,
		ReuseIdleMinutes: 30, ReusePresence: "lock+idle", NewCallerApproval: "on",
	}
}

func (e *Engine) settings() Settings {
	s := defaultSettings()
	if b, err := os.ReadFile(e.path("settings.json")); err == nil {
		_ = json.Unmarshal(b, &s)
	}
	if s.DefaultDuration == "" {
		s.DefaultDuration = "1h"
	}
	if s.IdleMinutes <= 0 {
		s.IdleMinutes = 5
	}
	if s.ReuseIdleMinutes < 0 {
		s.ReuseIdleMinutes = 0
	}
	if s.ReusePresence == "" {
		s.ReusePresence = "lock+idle"
	}
	if s.NewCallerApproval == "" {
		s.NewCallerApproval = "on"
	}
	for p, d := range s.Durations { // v0.1 -> v1 layout
		s.policyFor(p).Duration = d
	}
	s.Durations = nil
	return s
}

func (e *Engine) saveSettings(s Settings) error {
	if err := e.ensureDirs(); err != nil {
		return err
	}
	sort.Strings(s.Keep)
	b, _ := json.MarshalIndent(s, "", "  ")
	return writeFileAtomic(e.path("settings.json"), b, 0o600)
}

func (s *Settings) policyFor(profile string) *ProfilePolicy {
	if s.Profiles == nil {
		s.Profiles = map[string]*ProfilePolicy{}
	}
	p := s.Profiles[profile]
	if p == nil {
		p = &ProfilePolicy{}
		s.Profiles[profile] = p
	}
	return p
}

func (s Settings) policy(profile string) ProfilePolicy {
	if p := s.Profiles[profile]; p != nil {
		return *p
	}
	return ProfilePolicy{}
}

func (s Settings) isKept(profile string) bool {
	for _, k := range s.Keep {
		if strings.EqualFold(k, profile) {
			return true
		}
	}
	return false
}

func (s Settings) sensitive() []string {
	if len(s.SensitiveCommands) > 0 {
		return s.SensitiveCommands
	}
	return defaultSensitiveCommands
}

const (
	tierBase  = "base"  // GetSessionToken (no roles configured)
	tierRead  = "read"  // AssumeRole(read role)
	tierWrite = "write" // AssumeRole(write role): short, fresh Hello per session
)

// resolveTier maps the requested tier to what the policy supports.
func (s Settings) resolveTier(profile, tier string) (string, error) {
	p := s.policy(profile)
	switch tier {
	case "", tierBase, tierRead:
		if p.ReadRole != "" {
			return tierRead, nil
		}
		return tierBase, nil
	case tierWrite:
		if p.WriteRole == "" {
			return "", fmt.Errorf("profile %s has no write role (zsp tier set --profile %s --write-role ...)", profile, profile)
		}
		return tierWrite, nil
	}
	return "", fmt.Errorf("unknown tier %q (read or write)", tier)
}

func (s Settings) durationFor(profile, tier string) time.Duration {
	p := s.policy(profile)
	if tier == tierWrite {
		d, err := parseDurationRange(p.WriteDuration, 15*time.Minute, time.Hour)
		if err != nil || p.WriteDuration == "" {
			return 15 * time.Minute
		}
		return d
	}
	v := s.DefaultDuration
	if p.Duration != "" {
		v = p.Duration
	}
	d, err := parseSessionDuration(v)
	if err != nil {
		return time.Hour
	}
	return d
}

// parseSessionDuration accepts Go durations ("90m", "1h30m") between 15 minutes
// and 12 hours, the same window as the Mac tool and STS GetSessionToken.
func parseSessionDuration(v string) (time.Duration, error) {
	return parseDurationRange(v, 15*time.Minute, 12*time.Hour)
}

func parseDurationRange(v string, lo, hi time.Duration) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil {
		return 0, fmt.Errorf("bad duration %q (use e.g. 15m, 1h, 8h)", v)
	}
	if d < lo || d > hi {
		return 0, fmt.Errorf("duration must be between %s and %s", lo, hi)
	}
	return d, nil
}

// refreshMargin: a cached session with less than this left is not handed out,
// so a long `terraform apply` does not run out of credentials halfway.
func refreshMargin(d time.Duration) time.Duration {
	m := d / 5
	if m > 5*time.Minute {
		m = 5 * time.Minute
	}
	if m < time.Minute {
		m = time.Minute
	}
	return m
}
