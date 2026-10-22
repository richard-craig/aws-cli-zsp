package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Session is a short-lived STS credential set.
type Session struct {
	AccessKeyID     string        `json:"AccessKeyId"`
	SecretAccessKey string        `json:"SecretAccessKey"`
	SessionToken    string        `json:"SessionToken"`
	Expiration      time.Time     `json:"Expiration"`
	MFA             bool          `json:"mfa"`
	Source          string        `json:"source"` // "hello" or "phone"
	Tier            string        `json:"tier"`
	Issued          time.Time     `json:"issued"`
	Duration        time.Duration `json:"duration"`
	OSSession       uint32        `json:"os_session,omitempty"` // Windows session it was issued to (service mode)
}

func sessionKey(profile, tier string) string { return profile + "~" + tier }

func splitSessionKey(k string) (profile, tier string) {
	if i := strings.LastIndex(k, "~"); i >= 0 {
		return k[:i], k[i+1:]
	}
	return k, tierBase
}

// SessionCache stores sessions. User mode: TPM-sealed files. Service mode:
// process memory of the broker only (never on disk).
type SessionCache interface {
	Get(key string, minLeft time.Duration) (*Session, error)
	Put(key string, s *Session) error
	// Remove drops sessions that match. profile "" matches every profile.
	Remove(profile string, match func(*SessionInfo) bool) int
	List() []SessionInfo
}

type SessionInfo struct {
	Profile, Tier, Source string
	Expires               time.Time
	OSSession             uint32
}

func anySession(*SessionInfo) bool { return true }

// --- user mode: sealed files ------------------------------------------------------

type fileCache struct{ e *Engine }

func (c fileCache) file(key string) string { return c.e.path("sessions", key+".sealed") }

func (c fileCache) Get(key string, minLeft time.Duration) (*Session, error) {
	env, err := readEnvelope(c.file(key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Cheap expiry check on the clear-text header before touching the TPM.
	if exp, perr := time.Parse(time.RFC3339, env.Meta["expires"]); perr == nil && time.Until(exp) < minLeft {
		return nil, nil
	}
	pt, err := env.open(c.e.Quiet, "")
	if err != nil {
		return nil, err
	}
	defer zero(pt)
	var s Session
	if err := json.Unmarshal(pt, &s); err != nil {
		return nil, err
	}
	if time.Until(s.Expiration) < minLeft {
		return nil, nil
	}
	return &s, nil
}

func (c fileCache) Put(key string, s *Session) error {
	pt, _ := json.Marshal(s)
	defer zero(pt)
	env, err := seal(c.e.Quiet, kindQuiet, "session", key, pt, map[string]string{
		"expires": s.Expiration.UTC().Format(time.RFC3339),
		"source":  s.Source,
		"tier":    s.Tier,
	})
	if err != nil {
		return err
	}
	return writeEnvelope(c.file(key), env)
}

func (c fileCache) infos() []SessionInfo {
	files, _ := filepath.Glob(c.e.path("sessions", "*.sealed"))
	var out []SessionInfo
	for _, f := range files {
		env, err := readEnvelope(f)
		if err != nil {
			continue
		}
		p, t := splitSessionKey(strings.TrimSuffix(filepath.Base(f), ".sealed"))
		exp, _ := time.Parse(time.RFC3339, env.Meta["expires"])
		out = append(out, SessionInfo{Profile: p, Tier: t, Source: env.Meta["source"], Expires: exp})
	}
	return out
}

func (c fileCache) Remove(profile string, match func(*SessionInfo) bool) int {
	n := 0
	for _, i := range c.infos() {
		if profile != "" && i.Profile != profile {
			continue
		}
		if match(&i) && os.Remove(c.file(sessionKey(i.Profile, i.Tier))) == nil {
			n++
		}
	}
	return n
}

func (c fileCache) List() []SessionInfo {
	var out []SessionInfo
	for _, i := range c.infos() {
		if time.Now().Before(i.Expires) {
			out = append(out, i)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Profile+out[a].Tier < out[b].Profile+out[b].Tier })
	return out
}

// --- service mode: memory only ------------------------------------------------------

type memCache struct {
	mu sync.Mutex
	m  map[string]*Session
}

func newMemCache() *memCache { return &memCache{m: map[string]*Session{}} }

func (c *memCache) Get(key string, minLeft time.Duration) (*Session, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.m[key]
	if s == nil || time.Until(s.Expiration) < minLeft {
		return nil, nil
	}
	cp := *s
	return &cp, nil
}

func (c *memCache) Put(key string, s *Session) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := *s
	c.m[key] = &cp
	return nil
}

func (c *memCache) Remove(profile string, match func(*SessionInfo) bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for k, s := range c.m {
		p, t := splitSessionKey(k)
		i := SessionInfo{Profile: p, Tier: t, Source: s.Source, Expires: s.Expiration, OSSession: s.OSSession}
		if (profile == "" || p == profile) && match(&i) {
			s.SecretAccessKey, s.SessionToken = "", ""
			delete(c.m, k)
			n++
		}
	}
	return n
}

func (c *memCache) List() []SessionInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []SessionInfo
	for k, s := range c.m {
		if time.Now().After(s.Expiration) {
			continue
		}
		p, t := splitSessionKey(k)
		out = append(out, SessionInfo{Profile: p, Tier: t, Source: s.Source, Expires: s.Expiration, OSSession: s.OSSession})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Profile+out[a].Tier < out[b].Profile+out[b].Tier })
	return out
}
