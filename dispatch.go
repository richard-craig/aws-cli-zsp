package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Request is one operation. In user mode zsp.exe dispatches it to an in-process
// engine; in service mode it travels over the named pipe and the broker
// dispatches it to the engine for the authenticated Windows user.
type Request struct {
	Op      string            `json:"op"`
	Profile string            `json:"profile,omitempty"`
	Tier    string            `json:"tier,omitempty"`
	Args    map[string]string `json:"args,omitempty"`
	Key     *KeyPayload       `json:"key,omitempty"`    // seal
	Bundle  *MigrationBundle  `json:"bundle,omitempty"` // migrate
	Snap    *ConfigSnapshot   `json:"snap,omitempty"`
	Caller  CallerInfo        `json:"caller"` // client's view; the broker replaces it with its own
}

type Response struct {
	Session *Session        `json:"session,omitempty"`
	Key     *KeyPayload     `json:"key,omitempty"` // restore only
	Text    string          `json:"text,omitempty"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// StatusData is returned by the "status" op.
type StatusData struct {
	Mode     Mode            `json:"mode"`
	Enrolled bool            `json:"enrolled"`
	Backend  string          `json:"backend"`
	Settings Settings        `json:"settings"`
	Profiles []ProfileStatus `json:"profiles"`
	Ship     *shipState      `json:"ship_state,omitempty"`
	Checks   []Check         `json:"checks,omitempty"`
}

type ProfileStatus struct {
	Name       string            `json:"name"`
	Meta       map[string]string `json:"meta"`
	Sessions   []SessionInfo     `json:"sessions"`
	LastUsed   time.Time         `json:"last_used"`
	LastCaller string            `json:"last_caller"`
	Policy     ProfilePolicy     `json:"policy"`
	Phone      bool              `json:"phone"`
	Incoming   bool              `json:"incoming"`
}

func arg(r *Request, k string) string { return strings.TrimSpace(r.Args[k]) }

func dispatch(e *Engine, r *Request) (*Response, error) {
	e.Caller = r.Caller
	allowedUnenrolled := map[string]bool{"status": true, "ping": true, "audit-show": true, "audit-verify": true, "lock-clear": true}
	if e.Guarded == nil && !allowedUnenrolled[r.Op] {
		return nil, errNotEnrolled
	}
	if r.Profile != "" {
		if _, err := safeProfileName(r.Profile); err != nil {
			return nil, err
		}
	}
	cr := CredRequest{Profile: r.Profile, Tier: r.Tier, Snap: r.Snap}
	ok := func(err error) (*Response, error) { return &Response{}, err }

	switch r.Op {
	case "ping":
		return &Response{Text: "pong " + version_}, nil
	case "credential":
		s, err := e.Credential(cr)
		if err != nil {
			return nil, err
		}
		return &Response{Session: s}, nil
	case "approve":
		s, err := e.Approve(r.Profile, r.Tier, arg(r, "code"), r.Snap)
		if err != nil {
			return nil, err
		}
		return &Response{Session: s}, nil
	case "seal":
		if r.Key == nil {
			return nil, errors.New("no key")
		}
		res, err := e.ImportKey(r.Profile, r.Key, arg(r, "source"))
		r.Key.wipe()
		return &Response{Text: res}, err
	case "migrate":
		if r.Bundle == nil {
			return nil, errors.New("no bundle")
		}
		return ok(e.ImportBundle(r.Profile, r.Bundle))
	case "status":
		return e.statusResponse()
	case "test":
		return ok(e.Test(cr))
	case "check":
		return ok(e.Check(r.Profile, r.Snap))
	case "rotate":
		return ok(e.Rotate(r.Profile, r.Snap))
	case "revoke":
		return ok(e.Revoke(r.Profile, r.Snap))
	case "adopt":
		return ok(e.Adopt(r.Profile, r.Snap))
	case "restore":
		k, err := e.Restore(r.Profile, arg(r, "force") == "1")
		if err != nil {
			return nil, err
		}
		return &Response{Key: k}, nil
	case "pin-reset":
		return ok(e.PinReset(r.Profile))
	case "mfa-enable":
		return ok(e.MFAEnable(r.Profile, arg(r, "device"), r.Snap))
	case "mfa-disable":
		return ok(e.MFADisable(r.Profile, r.Snap))
	case "mfa-enforce":
		return ok(e.MFAEnforce(r.Profile, true, r.Snap))
	case "mfa-unenforce":
		return ok(e.MFAEnforce(r.Profile, false, r.Snap))
	case "phone-add":
		return ok(e.PhoneAdd(r.Profile, r.Snap))
	case "phone-remove":
		return ok(e.PhoneRemove(r.Profile, r.Snap))
	case "netbind":
		return ok(e.Netbind(r.Profile, splitList(arg(r, "cidrs")), arg(r, "force") == "1", r.Snap))
	case "tier-set":
		p, err := e.TierSet(r.Profile, TierSpec{ReadRole: arg(r, "read"), WriteRole: arg(r, "write"),
			WriteDuration: arg(r, "write-duration"), WriteProfile: arg(r, "write-profile"), Verify: arg(r, "verify") != "0"}, r.Snap)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(p)
		return &Response{Data: b}, nil
	case "tier-clear":
		p, err := e.TierClear(r.Profile)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(p)
		return &Response{Data: b}, nil
	case "setting":
		return ok(e.SetSetting(r.Profile, arg(r, "name"), arg(r, "value")))
	case "guard-approve":
		return ok(e.GuardApprove(r.Snap))
	case "guard-status":
		found, bad, err := e.GuardDiff(r.Snap)
		if err != nil {
			return nil, err
		}
		b, _ := json.Marshal(map[string][]GuardFinding{"found": found, "unapproved": bad})
		return &Response{Data: b}, nil
	case "clear-sessions":
		n := e.Cache.Remove(r.Profile, anySession)
		e.Audit("sessions-cleared", r.Profile, true, fmt.Sprintf("%d removed", n), e.Caller.Desc)
		return &Response{Text: strconv.Itoa(n)}, nil
	case "lock-clear":
		n := e.clearOnLock()
		return &Response{Text: strconv.Itoa(n)}, nil
	case "callers-forget":
		if err := e.approve(r.Profile, "Forget the programs approved to use AWS keys"); err != nil {
			return nil, err
		}
		return &Response{Text: strconv.Itoa(e.forgetCallers(r.Profile))}, nil
	case "audit-show":
		entries, err := e.readAudit()
		if err != nil {
			return nil, err
		}
		n, _ := strconv.Atoi(arg(r, "n"))
		if n <= 0 {
			n = 30
		}
		if len(entries) > n {
			entries = entries[len(entries)-n:]
		}
		b, _ := json.Marshal(entries)
		return &Response{Data: b}, nil
	case "audit-verify":
		n, err := e.VerifyAudit()
		if err != nil {
			return nil, fmt.Errorf("audit chain BROKEN: %w", err)
		}
		return &Response{Text: strconv.Itoa(n)}, nil
	case "ship-setup":
		err := e.ShipSetup(arg(r, "bucket"), arg(r, "region"), arg(r, "prefix"), arg(r, "akid"), r.Args["secret"])
		delete(r.Args, "secret")
		return ok(err)
	case "ship-now":
		return ok(e.ShipNow())
	case "ship-off":
		return ok(e.ShipOff())
	case "enroll":
		return nil, errors.New("enroll is handled by the service")
	}
	return nil, fmt.Errorf("unknown operation %q", r.Op)
}

// clearOnLock drops Hello-issued sessions (not phone-approved ones) when the
// workstation locks, unless the user opted out. Write-tier sessions always go.
func (e *Engine) clearOnLock() int {
	keep := e.settings().KeepSessionsOnLock
	n := e.Cache.Remove("", func(i *SessionInfo) bool {
		if i.Tier == tierWrite {
			return true
		}
		return !keep && i.Source != "phone"
	})
	if n > 0 {
		e.Audit("sessions-cleared", "", true, fmt.Sprintf("workstation locked: %d session(s) dropped", n), "lock")
	}
	return n
}

func (e *Engine) statusResponse() (*Response, error) {
	sd := StatusData{Mode: e.Mode, Enrolled: e.Guarded != nil, Settings: e.settings()}
	if e.Quiet != nil {
		sd.Backend = e.Quiet.Name()
	}
	entries, _ := e.readAudit()
	last := map[string]AuditEntry{}
	for _, a := range entries {
		if a.Profile != "" && (a.Event == "session-used" || a.Event == "session-issued" || a.Event == "phone-approved") {
			last[a.Profile] = a
		}
	}
	sessions := map[string][]SessionInfo{}
	if e.Cache != nil {
		for _, s := range e.Cache.List() {
			sessions[s.Profile] = append(sessions[s.Profile], s)
		}
	}
	for _, p := range e.profiles() {
		env, _ := readEnvelope(e.keyPath(p))
		ps := ProfileStatus{Name: p, Sessions: sessions[p], Policy: sd.Settings.policy(p), Phone: e.hasPhoneCopy(p)}
		if env != nil {
			ps.Meta = env.Meta
		}
		if a, ok := last[p]; ok {
			ps.LastUsed, ps.LastCaller = a.TS, a.Caller
		}
		if _, err := readEnvelope(e.incomingPath(p)); err == nil {
			ps.Incoming = true
		}
		sd.Profiles = append(sd.Profiles, ps)
	}
	if sd.Settings.Ship != nil {
		s := e.loadShipState()
		sd.Ship = &s
	}
	sd.Checks = e.vaultChecks()
	b, _ := json.Marshal(sd)
	return &Response{Data: b}, nil
}

// vaultChecks are the health checks that need the vault itself.
func (e *Engine) vaultChecks() []Check {
	var cs []Check
	ps := e.profiles()
	cs = append(cs, Check{"Keys in the vault", len(ps) > 0, fmt.Sprintf("%d sealed: %s", len(ps), strings.Join(ps, ", ")), "zsp setup"})
	var inc, pinBad []string
	for _, p := range ps {
		if _, err := readEnvelope(e.incomingPath(p)); err == nil {
			inc = append(inc, p)
		}
		if _, err := e.LoadPin(p); err != nil {
			pinBad = append(pinBad, p+": "+err.Error())
		}
	}
	if len(inc) > 0 {
		cs = append(cs, Check{"Quarantined keys", false, "new keys written over MFA profiles: " + strings.Join(inc, ", "), "zsp adopt --profile <name>"})
	}
	cs = append(cs, Check{"Account pins", len(pinBad) == 0, orNone(pinBad, "all valid (or set on first use)"), "zsp pin reset --profile <name>"})
	if n, err := e.VerifyAudit(); err != nil {
		cs = append(cs, Check{"Audit trail", false, err.Error(), "investigate; CloudTrail is the authoritative record"})
	} else {
		cs = append(cs, Check{"Audit trail", true, fmt.Sprintf("chain intact, %d entries", n), ""})
	}
	st := e.settings()
	if st.Ship != nil {
		s := e.loadShipState()
		fresh := s.LastErr == "" && (s.LastShip.IsZero() || time.Since(s.LastShip) < 24*time.Hour)
		d := fmt.Sprintf("s3://%s/%s, %d entries shipped, last %s", st.Ship.Bucket, st.Ship.Prefix, s.Index, s.LastShip.Local().Format("Jan 02 15:04"))
		if s.LastErr != "" {
			d += ", last error: " + s.LastErr
		}
		cs = append(cs, Check{"Audit shipped off the PC", fresh, d, "zsp ship now"})
	} else {
		cs = append(cs, Check{"Audit shipped off the PC", true, "off (optional: zsp ship setup)", ""})
	}
	if b, err := e.loadBaseline(); err != nil {
		cs = append(cs, Check{"Config guard baseline", false, err.Error(), "zsp guard approve"})
	} else if b != nil {
		cs = append(cs, Check{"Config guard baseline", true, fmt.Sprintf("%d approved setting(s)", len(b.Approved)), ""})
	}
	return cs
}

func orNone(xs []string, ok string) string {
	if len(xs) == 0 {
		return ok
	}
	return strings.Join(xs, "; ")
}

// SetSetting changes one setting. Every change needs Windows Hello approval
// once there is a key in the vault, so malware cannot quietly weaken policy.
func (e *Engine) SetSetting(profile, name, value string) error {
	st := e.settings()
	onoff := func(v string) (bool, error) {
		switch strings.ToLower(v) {
		case "on", "true", "yes", "1":
			return true, nil
		case "off", "false", "no", "0":
			return false, nil
		}
		return false, fmt.Errorf("%s must be on or off", name)
	}
	var err error
	switch name {
	case "duration":
		if _, err = parseSessionDuration(value); err == nil {
			if profile == "" {
				st.DefaultDuration = value
			} else {
				st.policyFor(profile).Duration = value
			}
		}
	case "auto-move":
		st.AutoMove, err = onoff(value)
	case "keep":
		for _, k := range splitList(value) {
			if !st.isKept(k) {
				st.Keep = append(st.Keep, k)
			}
		}
	case "unkeep":
		var out []string
		for _, k := range st.Keep {
			drop := false
			for _, u := range splitList(value) {
				if strings.EqualFold(k, u) {
					drop = true
				}
			}
			if !drop {
				out = append(out, k)
			}
		}
		st.Keep = out
	case "idle-minutes":
		st.IdleMinutes, err = strconv.Atoi(value)
		if err == nil && (st.IdleMinutes < 1 || st.IdleMinutes > 240) {
			err = errors.New("idle-minutes must be 1-240")
		}
	case "reuse-idle-minutes":
		st.ReuseIdleMinutes, err = strconv.Atoi(value)
		if err == nil && (st.ReuseIdleMinutes < 0 || st.ReuseIdleMinutes > 720) {
			err = errors.New("reuse-idle-minutes must be 0-720")
		}
	case "reuse-presence":
		if value != "lock+idle" && value != "lock" && value != "off" {
			err = errors.New("reuse-presence must be lock+idle, lock or off")
		}
		st.ReusePresence = value
	case "keep-sessions-on-lock":
		st.KeepSessionsOnLock, err = onoff(value)
	case "new-caller-approval":
		var on bool
		on, err = onoff(value)
		st.NewCallerApproval = map[bool]string{true: "on", false: "off"}[on]
	case "sensitive-commands":
		if value == "default" {
			st.SensitiveCommands = nil
		} else {
			st.SensitiveCommands = splitList(value)
		}
	default:
		return fmt.Errorf("unknown setting %q", name)
	}
	if err != nil {
		return err
	}
	if err := e.approve(profile, fmt.Sprintf("Change zsp setting: %s = %s", name, truncate(value, 80))); err != nil {
		return err
	}
	if err := e.saveSettings(st); err != nil {
		return err
	}
	e.Audit("setting", profile, true, name+"="+truncate(value, 80), e.Caller.Desc)
	return nil
}
