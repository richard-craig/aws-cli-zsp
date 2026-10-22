package main

import (
	"errors"
	"os"
	"strings"
)

// A minimal, line-preserving INI model for ~/.aws/credentials and ~/.aws/config.
// Comments, ordering and unrelated sections survive a round trip untouched.

type iniLine struct {
	raw string
	key string // lower-cased key, "" for comments/blank lines
	val string
}

type iniSection struct {
	header string // raw header line, "" for the preamble
	name   string // section name as written, e.g. "default", "profile dev"
	lines  []iniLine
}

type iniFile struct {
	sections []*iniSection
	crlf     bool
}

func parseINI(text string) *iniFile {
	f := &iniFile{crlf: strings.Contains(text, "\r\n")}
	text = strings.ReplaceAll(text, "\r\n", "\n")
	cur := &iniSection{}
	f.sections = append(f.sections, cur)
	if text == "" {
		return f
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for _, raw := range lines {
		t := strings.TrimSpace(raw)
		if strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]") {
			cur = &iniSection{header: raw, name: strings.TrimSpace(t[1 : len(t)-1])}
			f.sections = append(f.sections, cur)
			continue
		}
		l := iniLine{raw: raw}
		if t != "" && !strings.HasPrefix(t, "#") && !strings.HasPrefix(t, ";") {
			if i := strings.Index(t, "="); i > 0 {
				l.key = strings.ToLower(strings.TrimSpace(t[:i]))
				l.val = strings.TrimSpace(t[i+1:])
			}
		}
		cur.lines = append(cur.lines, l)
	}
	return f
}

func readINI(path string) (*iniFile, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return parseINI(""), nil
	}
	if err != nil {
		return nil, err
	}
	return parseINI(string(b)), nil
}

func (f *iniFile) String() string {
	var b strings.Builder
	nl := "\n"
	if f.crlf {
		nl = "\r\n"
	}
	for _, s := range f.sections {
		if s.header != "" {
			b.WriteString(s.header + nl)
		}
		for _, l := range s.lines {
			b.WriteString(l.raw + nl)
		}
	}
	return b.String()
}

func (f *iniFile) section(name string) *iniSection {
	for _, s := range f.sections {
		if s.header != "" && s.name == name {
			return s
		}
	}
	return nil
}

func (f *iniFile) ensureSection(name string) *iniSection {
	if s := f.section(name); s != nil {
		return s
	}
	// Keep a blank line between sections for readability.
	if last := f.sections[len(f.sections)-1]; len(last.lines) > 0 && strings.TrimSpace(last.lines[len(last.lines)-1].raw) != "" {
		last.lines = append(last.lines, iniLine{raw: ""})
	}
	s := &iniSection{header: "[" + name + "]", name: name}
	f.sections = append(f.sections, s)
	return s
}

func (f *iniFile) removeSection(name string) {
	out := f.sections[:0]
	for _, s := range f.sections {
		if s.header != "" && s.name == name {
			continue
		}
		out = append(out, s)
	}
	f.sections = out
}

func (s *iniSection) get(key string) (string, bool) {
	for _, l := range s.lines {
		if l.key == key {
			return l.val, true
		}
	}
	return "", false
}

func (s *iniSection) set(key, val string) {
	for i, l := range s.lines {
		if l.key == key {
			s.lines[i] = iniLine{raw: key + " = " + val, key: key, val: val}
			return
		}
	}
	// insert before trailing blank lines
	at := len(s.lines)
	for at > 0 && strings.TrimSpace(s.lines[at-1].raw) == "" {
		at--
	}
	nl := iniLine{raw: key + " = " + val, key: key, val: val}
	s.lines = append(s.lines[:at], append([]iniLine{nl}, s.lines[at:]...)...)
}

func (s *iniSection) del(keys ...string) {
	out := s.lines[:0]
	for _, l := range s.lines {
		drop := false
		for _, k := range keys {
			if l.key == k {
				drop = true
			}
		}
		if !drop {
			out = append(out, l)
		}
	}
	s.lines = out
}

func (s *iniSection) empty() bool {
	for _, l := range s.lines {
		if strings.TrimSpace(l.raw) != "" {
			return false
		}
	}
	return true
}

// Profile-name mapping: credentials uses [name]; config uses [default] or [profile name].
func configSectionName(profile string) string {
	if profile == "default" {
		return "default"
	}
	return "profile " + profile
}

func profileFromConfigSection(name string) (string, bool) {
	if name == "default" {
		return "default", true
	}
	if strings.HasPrefix(name, "profile ") {
		return strings.TrimSpace(strings.TrimPrefix(name, "profile ")), true
	}
	return "", false
}
