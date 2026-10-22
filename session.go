package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func humanDuration(d time.Duration) string {
	if d%time.Hour == 0 {
		if h := int(d / time.Hour); h == 1 {
			return "1-hour"
		} else {
			return fmt.Sprintf("%d-hour", h)
		}
	}
	return fmt.Sprintf("%d-minute", int(d/time.Minute))
}

// regionFromConfig reads `region` for a profile from a config snapshot.
func regionFromConfig(snap *ConfigSnapshot, profile string) string {
	if r := os.Getenv("ZSP_STS_REGION"); r != "" {
		return r
	}
	if snap == nil {
		return ""
	}
	if s := parseINI(snap.Config).section(configSectionName(profile)); s != nil {
		if r, ok := s.get("region"); ok {
			return r
		}
	}
	return ""
}

// CredRequest is one credential_process call.
type CredRequest struct {
	Profile string
	Tier    string // "", "read" or "write"
	Snap    *ConfigSnapshot
}

// Credential is what credential_process calls: a cached session when policy
// allows, otherwise Windows Hello -> STS.
func (e *Engine) Credential(r CredRequest) (*Session, error) {
	profile := r.Profile
	if _, err := safeProfileName(profile); err != nil {
		return nil, err
	}
	st := e.settings()
	tier, err := st.resolveTier(profile, r.Tier)
	if err != nil {
		return nil, err
	}
	if _, err := e.KeyEnvelope(profile); err != nil {
		return nil, err
	}
	caller := e.Caller.Desc
	if err := e.guardCheck(profile, r.Snap); err != nil {
		return nil, err
	}
	d := st.durationFor(profile, tier)
	key := sessionKey(profile, tier)

	if s, err := e.reuse(profile, tier, key, d, st); err != nil || s != nil {
		return s, err
	}

	// One prompt at a time per profile+tier: a second command started in
	// parallel waits here and then picks up the session the first one created.
	unlock, err := e.lock("session-"+key, 150*time.Second)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if s, err := e.reuse(profile, tier, key, d, st); err != nil || s != nil {
		return s, err
	}

	if present, why := e.presence(time.Duration(st.IdleMinutes) * time.Minute); !present {
		msg := fmt.Sprintf("nobody is at this PC (%s), so Windows Hello cannot be asked.", why)
		if e.hasPhoneCopy(profile) {
			t := ""
			if tier == tierWrite {
				t = " --tier write"
			}
			msg += fmt.Sprintf(" Ask the user for the 6-digit code from their authenticator app for '%s', then run:  zsp approve --profile %s%s <code>", profile, profile, t)
		} else {
			msg += " Phone approval is not set up for this profile (zsp phone add --profile " + profile + ")."
		}
		e.Audit("session-refused", profile, false, "no one present: "+why, caller)
		return nil, errors.New(msg)
	}

	what := humanDuration(d) + " session"
	switch tier {
	case tierRead:
		what = humanDuration(d) + " READ-ONLY session"
	case tierWrite:
		what = humanDuration(d) + " WRITE session"
	}
	who := caller
	if who == "" {
		who = "an unknown program"
	}
	prompt := fmt.Sprintf("Unlock AWS key '%s' for a %s.\nRequested by: %s", profile, what, truncate(who, 140))
	k, _, err := e.OpenKey(profile, prompt)
	if err != nil {
		e.Audit("hello-declined", profile, false, err.Error(), caller)
		return nil, fmt.Errorf("Windows Hello: %w", err)
	}
	defer k.wipe()

	s, err := e.issue(profile, tier, k, d, r.Snap, "hello")
	if err != nil {
		e.Audit("session-refused", profile, false, err.Error(), caller)
		return nil, err
	}
	s.OSSession = e.Caller.OSSession
	if err := e.Cache.Put(key, s); err != nil {
		return nil, err
	}
	if id, always, _ := e.Caller.identity(); e.Mode == ModeService && !always && id != "" {
		e.rememberCaller(profile, id, e.Caller.Image)
	}
	e.Audit("session-issued", profile, true, fmt.Sprintf("%s %s, mfa=%v, expires %s", tier, humanDuration(d), s.MFA, s.Expiration.Format(time.RFC3339)), caller)
	return s, nil
}

// reuse returns a cached session if every v0.2/v1.0 policy allows it, nil if a
// new one must be issued, or an error if the request must be refused.
func (e *Engine) reuse(profile, tier, key string, d time.Duration, st Settings) (*Session, error) {
	s, err := e.Cache.Get(key, refreshMargin(d))
	if err != nil || s == nil {
		return nil, nil
	}
	caller := e.Caller.Desc

	// v0.2: presence on reuse. A Hello session is not handed out while the
	// screen is locked or the PC is idle. Phone-approved sessions were approved
	// remotely on purpose, so only the lock applies to them... and not even that:
	// the person approving is by definition away from the PC.
	if s.Source != "phone" && st.ReusePresence != "off" {
		limit := time.Duration(st.ReuseIdleMinutes) * time.Minute
		if st.ReusePresence == "lock" {
			limit = 0
		}
		if tier == tierWrite {
			limit = time.Duration(st.IdleMinutes) * time.Minute
		}
		if ok, why := e.presence(limit); !ok {
			e.Audit("session-withheld", profile, false, "cached session not handed out: "+why, caller)
			return nil, fmt.Errorf("a session for '%s' is cached, but it is not handed out while %s. Unlock the PC / touch the keyboard and try again", profile, why)
		}
	}

	// Credential-minting commands always need a fresh approval.
	if cmd := e.Caller.sensitiveCommand(st.sensitive()); cmd != "" {
		if err := e.approve(profile, fmt.Sprintf("'%s' wants to PRINT or MINT credentials from AWS key '%s' (%s).\nRequested by: %s", cmd, profile, tier, truncate(caller, 120))); err != nil {
			e.Audit("sensitive-declined", profile, false, cmd, caller)
			return nil, fmt.Errorf("Windows Hello: %w", err)
		}
		e.Audit("sensitive-approved", profile, true, cmd, caller)
		return s, nil
	}

	// v1.0: a program that has never used this profile needs one approval.
	if e.Mode == ModeService && st.NewCallerApproval != "off" {
		id, always, why := e.Caller.identity()
		if always || !e.callerKnown(profile, id) {
			reason := "a program that has not used this key before"
			if always {
				reason = why
			}
			if err := e.approve(profile, fmt.Sprintf("Allow %s to use AWS key '%s' (%s session already open)?\nRequested by: %s", reason, profile, tier, truncate(caller, 120))); err != nil {
				e.Audit("caller-declined", profile, false, reason, caller)
				return nil, fmt.Errorf("Windows Hello: %w", err)
			}
			if !always {
				e.rememberCaller(profile, id, e.Caller.Image)
			}
			e.Audit("caller-approved", profile, true, reason, caller)
		}
	}
	e.Audit("session-used", profile, true, tier, caller)
	return s, nil
}

// mfaFor returns the serial and code to send with an STS call, asking the user
// for a phone code when the profile is in phone-only mode.
func (e *Engine) mfaFor(profile string, k *KeyPayload) (serial, code string, err error) {
	switch k.mode() {
	case "pc":
		code, err = totpFresh(k.MFASeed)
		return k.MFASerial, code, err
	case "phone":
		code, err = e.ask(fmt.Sprintf("6-digit code from your authenticator app for AWS profile '%s': ", profile))
		if err != nil {
			return "", "", err
		}
		code = strings.TrimSpace(code)
		if !validSixDigits(code) {
			return "", "", errors.New("the code must be 6 digits")
		}
		return k.PhoneSerial, code, nil
	}
	return "", "", nil
}

// issue turns the long-lived key into a session for the tier. The account pin
// is checked with the long-lived key itself before anything is issued.
func (e *Engine) issue(profile, tier string, k *KeyPayload, d time.Duration, snap *ConfigSnapshot, source string) (*Session, error) {
	c := Creds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}
	region := regionFromConfig(snap, profile)
	arn, err := e.checkPin(profile, c, region, source)
	if err != nil {
		return nil, err
	}
	st := e.settings()
	pol := st.policy(profile)
	call := func(serial, code string) (*Session, error) {
		switch tier {
		case tierRead:
			return assumeRole(c, region, pol.ReadRole, roleSessionName(userNameFromArn(arn), profile, tier), d, serial, code)
		case tierWrite:
			return assumeRole(c, region, pol.WriteRole, roleSessionName(userNameFromArn(arn), profile, tier), d, serial, code)
		}
		return getSessionToken(c, region, d, serial, code)
	}
	serial, code, err := e.mfaFor(profile, k)
	if err != nil {
		return nil, err
	}
	s, err := call(serial, code)
	if err != nil && isMFAReuse(err) && k.mode() == "pc" {
		// AWS refuses a code twice. Wait for the next 30 s window and retry once.
		time.Sleep(time.Duration(31-time.Now().Unix()%30) * time.Second)
		if code, err = totpAt(k.MFASeed, time.Now()); err == nil {
			s, err = call(serial, code)
		}
	}
	if err != nil {
		return nil, err
	}
	s.Source, s.Tier, s.Duration = source, tier, d
	return s, nil
}

func isMFAReuse(err error) bool {
	var ae *AWSError
	return errors.As(err, &ae) && ae.Code == "AccessDenied" && strings.Contains(strings.ToLower(ae.Message), "multifactor")
}

// checkPin makes sure the long-lived key belongs to the account+user this
// profile was first pinned to. A swapped key gets no credentials.
func (e *Engine) checkPin(profile string, c Creds, region, source string) (string, error) {
	caller := e.Caller.Desc
	id, err := getCallerIdentity(c, region)
	if err != nil {
		return "", fmt.Errorf("check account pin: %w", err)
	}
	pin, err := e.LoadPin(profile)
	if err != nil {
		e.Audit("pin-invalid", profile, false, err.Error(), caller)
		return "", fmt.Errorf("account pin for '%s' is invalid: %w. Run `zsp pin reset --profile %s` if you changed it on purpose", profile, err, profile)
	}
	if pin == nil {
		if source == "phone" {
			return "", errors.New("this profile has no account pin yet; open one session at the PC first")
		}
		if _, err := e.CreatePin(profile, id.Account, id.Arn); err != nil {
			e.Audit("pin-declined", profile, false, err.Error(), caller)
			return "", fmt.Errorf("account pin not created: %w", err)
		}
		e.Audit("pin-created", profile, true, "account "+maskAccount(id.Account)+", "+shortArn(id.Arn), caller)
		return id.Arn, nil
	}
	if pin.Account != id.Account || pin.Arn != id.Arn {
		e.Audit("pin-mismatch", profile, false, fmt.Sprintf("expected %s/%s, key belongs to %s/%s",
			maskAccount(pin.Account), shortArn(pin.Arn), maskAccount(id.Account), shortArn(id.Arn)), caller)
		return "", fmt.Errorf("REFUSED: the key sealed as '%s' belongs to account %s (%s), but this profile is pinned to %s (%s). Someone may have swapped the key",
			profile, maskAccount(id.Account), shortArn(id.Arn), maskAccount(pin.Account), shortArn(pin.Arn))
	}
	return id.Arn, nil
}

// Phone approval ---------------------------------------------------------------------

func (e *Engine) Approve(profile, tier, code string, snap *ConfigSnapshot) (*Session, error) {
	caller := e.Caller.Desc
	if !validSixDigits(code) {
		return nil, errors.New("the code must be 6 digits")
	}
	st := e.settings()
	tier, err := st.resolveTier(profile, tier)
	if err != nil {
		return nil, err
	}
	if err := e.guardCheck(profile, snap); err != nil {
		return nil, err
	}
	pc, err := e.loadPhoneCopy(profile)
	if err != nil {
		return nil, fmt.Errorf("phone approval is not set up for '%s'", profile)
	}
	k := &KeyPayload{AccessKeyID: pc.AccessKeyID, SecretAccessKey: pc.SecretAccessKey, MFAMode: "phone", PhoneSerial: pc.PhoneSerial}
	defer k.wipe()
	pc.SecretAccessKey = ""
	d := st.durationFor(profile, tier)
	codeUI := &fixedCodeUI{UI: e.UI, code: code}
	saved := e.UI
	e.UI = codeUI
	s, err := e.issue(profile, tier, k, d, snap, "phone")
	e.UI = saved
	if err != nil {
		e.Audit("phone-refused", profile, false, err.Error(), caller)
		return nil, fmt.Errorf("AWS refused the code: %w", err)
	}
	if err := e.Cache.Put(sessionKey(profile, tier), s); err != nil {
		return nil, err
	}
	e.Audit("phone-approved", profile, true, tier+" "+humanDuration(d), caller)
	return s, nil
}

// fixedCodeUI answers the MFA code question with a code given up front.
type fixedCodeUI struct {
	UI
	code string
}

func (f *fixedCodeUI) Ask(string) (string, error) { return f.code, nil }

func (f *fixedCodeUI) Printf(format string, a ...any) {
	if f.UI != nil {
		f.UI.Printf(format, a...)
	}
}

func (f *fixedCodeUI) HelloUnwrap(b []byte, p string) ([]byte, error) {
	if f.UI == nil {
		return nil, errors.New("no client to approve with Windows Hello")
	}
	return f.UI.HelloUnwrap(b, p)
}

type processCreds struct {
	Version         int    `json:"Version"`
	AccessKeyID     string `json:"AccessKeyId"`
	SecretAccessKey string `json:"SecretAccessKey"`
	SessionToken    string `json:"SessionToken"`
	Expiration      string `json:"Expiration"`
}

func credentialProcessJSON(s *Session) []byte {
	b, _ := json.Marshal(processCreds{
		Version: 1, AccessKeyID: s.AccessKeyID, SecretAccessKey: s.SecretAccessKey,
		SessionToken: s.SessionToken, Expiration: s.Expiration.UTC().Format(time.RFC3339),
	})
	return b
}
