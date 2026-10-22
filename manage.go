package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

const (
	policyRequireMFA = "aws-cli-zsp-require-mfa"
	policyRevoke     = "aws-cli-zsp-revoke-older-sessions"
	policySourceIP   = "aws-cli-zsp-source-ip"
)

func rolePolicyName(base, user string) string {
	n := base + "-" + sessionNameBad.ReplaceAllString(user, "-")
	if len(n) > 128 {
		n = n[:128]
	}
	return n
}

// adminCreds gives credentials suitable for IAM calls. With MFA it mints a
// 15-minute MFA session, which satisfies both the "require MFA" policy and its
// "MFA in the last five minutes" clause for creating keys and policies.
func (e *Engine) adminCreds(profile string, k *KeyPayload, snap *ConfigSnapshot) (Creds, error) {
	if k.mode() == "" {
		return Creds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}, nil
	}
	region := regionFromConfig(snap, profile)
	c := Creds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}
	serial, code, err := e.mfaFor(profile, k)
	if err != nil {
		return Creds{}, err
	}
	s, err := getSessionToken(c, region, 15*time.Minute, serial, code)
	if err != nil && isMFAReuse(err) && k.mode() == "pc" {
		time.Sleep(time.Duration(31-time.Now().Unix()%30) * time.Second)
		if code, err = totpAt(k.MFASeed, time.Now()); err == nil {
			s, err = getSessionToken(c, region, 15*time.Minute, serial, code)
		}
	}
	if err != nil {
		return Creds{}, fmt.Errorf("MFA session for admin action: %w", err)
	}
	return Creds{s.AccessKeyID, s.SecretAccessKey, s.SessionToken}, nil
}

func (e *Engine) whoAmI(profile string, k *KeyPayload, c Creds, snap *ConfigSnapshot) (user, arn string, err error) {
	id, err := getCallerIdentity(c, regionFromConfig(snap, profile))
	if err != nil {
		return "", "", err
	}
	u := userNameFromArn(id.Arn)
	if u == "" {
		return "", "", fmt.Errorf("%s is not an IAM user key (%s)", profile, id.Arn)
	}
	k.UserName = u
	return u, id.Arn, nil
}

func (e *Engine) openForAdmin(profile, action string, snap *ConfigSnapshot) (*KeyPayload, *Envelope, Creds, string, error) {
	k, env, err := e.OpenKey(profile, fmt.Sprintf("%s for AWS key '%s'.\nRequested by: %s", action, profile, truncate(e.Caller.Desc, 120)))
	if err != nil {
		return nil, nil, Creds{}, "", err
	}
	c, err := e.adminCreds(profile, k, snap)
	if err != nil {
		k.wipe()
		return nil, nil, Creds{}, "", err
	}
	user, _, err := e.whoAmI(profile, k, c, snap)
	if err != nil {
		k.wipe()
		return nil, nil, Creds{}, "", err
	}
	return k, env, c, user, nil
}

// Test --------------------------------------------------------------------------------

func (e *Engine) Test(r CredRequest) error {
	s, err := e.Credential(r)
	if err != nil {
		return err
	}
	id, err := getCallerIdentity(Creds{s.AccessKeyID, s.SecretAccessKey, s.SessionToken}, regionFromConfig(r.Snap, r.Profile))
	if err != nil {
		return err
	}
	e.printf("OK  %s (%s) -> account %s, %s, session until %s (mfa=%v)\n", r.Profile, s.Tier, id.Account, id.Arn,
		s.Expiration.Local().Format("15:04"), s.MFA)
	return nil
}

// Check in AWS --------------------------------------------------------------------------

func (e *Engine) Check(profile string, snap *ConfigSnapshot) error {
	k, _, c, user, err := e.openForAdmin(profile, "Check in IAM", snap)
	if err != nil {
		return err
	}
	defer k.wipe()
	e.printf("%s\n  user     %s\n  this key %s\n", profile, user, maskKeyID(k.AccessKeyID))
	keys, err := iamListAccessKeys(c, user)
	if isAWSCode(err, "AccessDenied") {
		e.printf("  access   read-only · client's key (this user may not manage itself; rotate/revoke/MFA are not offered)\n")
		e.Audit("check", profile, true, "read-only key", e.Caller.Desc)
		return e.updateMeta(profile, map[string]string{"readonly": "yes", "user_name": user})
	}
	if err != nil {
		return err
	}
	for _, ak := range keys {
		last := "never used"
		if lu, err := iamKeyLastUsed(c, ak.AccessKeyID); err == nil && !lu.LastUsedDate.IsZero() {
			last = fmt.Sprintf("last used %s (%s, %s)", lu.LastUsedDate.Local().Format("2006-01-02 15:04"), lu.ServiceName, lu.Region)
		}
		mark := " "
		if ak.AccessKeyID == k.AccessKeyID {
			mark = "*"
		}
		e.printf("  %s key    %s  %-8s created %s, %s\n", mark, maskKeyID(ak.AccessKeyID), ak.Status, ak.CreateDate.Format("2006-01-02"), last)
	}
	enforced, _ := iamHasUserPolicy(c, user, policyRequireMFA)
	bound, _ := iamHasUserPolicy(c, user, policySourceIP)
	e.printf("  mfa      mode: %s   AWS requires MFA: %v   source-IP bound: %v\n", orDash(k.mode()), enforced, bound)
	pol := e.settings().policy(profile)
	if pol.ReadRole != "" || pol.WriteRole != "" {
		e.printf("  tiers    read: %s\n           write: %s (profile %s)\n", orDash(pol.ReadRole), orDash(pol.WriteRole), orDash(pol.WriteProfile))
	}
	set := map[string]string{"readonly": "", "user_name": user, "enforced": "", "netbind": ""}
	if enforced {
		set["enforced"] = "yes"
	}
	if bound {
		set["netbind"] = "yes"
	}
	e.Audit("check", profile, true, fmt.Sprintf("%d keys for %s", len(keys), user), e.Caller.Desc)
	return e.updateMeta(profile, set)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// Revoke ---------------------------------------------------------------------------------

func revokeUserPolicy(t time.Time) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"RevokeSessionsIssuedBefore","Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"%s"}}}]}`,
		t.UTC().Format(time.RFC3339))
}

// revokeRolePolicy only hits this user's zsp sessions of the role, never other
// people's sessions of the same role.
func revokeRolePolicy(t time.Time, user string) string {
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"RevokeZspSessionsIssuedBefore","Effect":"Deny","Action":"*","Resource":"*","Condition":{"DateLessThan":{"aws:TokenIssueTime":"%s"},"StringLike":{"aws:userid":"*:zsp-%s-*"}}}]}`,
		t.UTC().Format(time.RFC3339), sessionNameBad.ReplaceAllString(user, "-"))
}

func (e *Engine) roles(profile string) []string {
	pol := e.settings().policy(profile)
	var out []string
	for _, r := range []string{pol.ReadRole, pol.WriteRole} {
		if n := roleNameFromArn(r); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func (e *Engine) Revoke(profile string, snap *ConfigSnapshot) error {
	k, _, c, user, err := e.openForAdmin(profile, "REVOKE every session issued", snap)
	if err != nil {
		return err
	}
	defer k.wipe()
	now := time.Now()
	if err := iamPutUserPolicy(c, user, policyRevoke, revokeUserPolicy(now)); err != nil {
		e.Audit("revoke", profile, false, err.Error(), e.Caller.Desc)
		return err
	}
	var roleErrs []string
	for _, r := range e.roles(profile) {
		if err := iamPutRolePolicy(c, r, rolePolicyName(policyRevoke, user), revokeRolePolicy(now, user)); err != nil {
			roleErrs = append(roleErrs, r+": "+err.Error())
		}
	}
	e.clearSessions(profile)
	e.Audit("revoke", profile, len(roleErrs) == 0, "denied all tokens issued before "+now.UTC().Format(time.RFC3339)+strings.Join(roleErrs, "; "), e.Caller.Desc)
	e.printf("Revoked: every session for %s issued before %s is now denied by AWS. The next command asks for Windows Hello.\n",
		profile, now.Local().Format("15:04:05"))
	if len(roleErrs) > 0 {
		return fmt.Errorf("user sessions revoked, but role sessions were NOT: %s (the IAM user needs iam:PutRolePolicy on its zsp roles; see deploy/tiered-roles.yaml)", strings.Join(roleErrs, "; "))
	}
	return nil
}

// Rotate ----------------------------------------------------------------------------------

func (e *Engine) Rotate(profile string, snap *ConfigSnapshot) error {
	k, env, c, user, err := e.openForAdmin(profile, "ROTATE (create new key, swap it in, delete the old one)", snap)
	if err != nil {
		return err
	}
	defer k.wipe()
	pin, _ := e.LoadPin(profile)
	keys, err := iamListAccessKeys(c, user)
	if err != nil {
		return err
	}
	if len(keys) >= 2 {
		return fmt.Errorf("%s already has two access keys; delete the unused one in IAM first", user)
	}
	newID, newSecret, err := iamCreateAccessKey(c, user)
	if err != nil {
		e.Audit("rotate", profile, false, "create: "+err.Error(), e.Caller.Desc)
		return err
	}
	fail := func(stage string, err error) error {
		_ = iamDeleteAccessKey(c, user, newID) // roll back: the old key stays in service
		e.Audit("rotate", profile, false, stage+": "+err.Error(), e.Caller.Desc)
		return fmt.Errorf("rotation stopped at %s, old key kept: %w", stage, err)
	}
	nc := Creds{AccessKeyID: newID, SecretAccessKey: newSecret}
	var id *CallerIdentity
	for i := 0; i < 12; i++ { // new IAM keys take a few seconds to become usable
		if id, err = getCallerIdentity(nc, regionFromConfig(snap, profile)); err == nil {
			break
		}
		time.Sleep(2500 * time.Millisecond)
	}
	if err != nil {
		return fail("verify new key", err)
	}
	if pin != nil && id.Arn != pin.Arn {
		return fail("verify new key", fmt.Errorf("new key belongs to %s", id.Arn))
	}
	oldID := k.AccessKeyID
	k.AccessKeyID, k.SecretAccessKey = newID, newSecret
	if err := e.reseal(profile, k, env.Meta, nil); err != nil {
		return fail("seal new key", err)
	}
	if pc, err := e.loadPhoneCopy(profile); err == nil {
		pc.AccessKeyID, pc.SecretAccessKey = newID, newSecret
		if err := e.savePhoneCopy(profile, pc); err != nil {
			return fail("update phone copy", err)
		}
	}
	if err := iamDeleteAccessKey(c, user, oldID); err != nil {
		e.Audit("rotate", profile, false, "new key sealed, deleting old key failed: "+err.Error(), e.Caller.Desc)
		return fmt.Errorf("new key is in the vault, but deleting %s failed: %w (delete it in IAM)", maskKeyID(oldID), err)
	}
	e.clearSessions(profile)
	e.Audit("rotate", profile, true, maskKeyID(oldID)+" -> "+maskKeyID(newID), e.Caller.Desc)
	e.printf("Rotated %s: %s -> %s (old key deleted)\n", profile, maskKeyID(oldID), maskKeyID(newID))
	return nil
}

// MFA -------------------------------------------------------------------------------------

var mfaNameRe = regexp.MustCompile(`[^\w+=,.@-]`)

func mfaDeviceName(prefix, user string) string {
	host, _ := os.Hostname()
	n := mfaNameRe.ReplaceAllString(prefix+"-"+host+"-"+user, "-")
	if len(n) > 100 {
		n = n[:100]
	}
	return n
}

func groupSeed(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// registerPhoneDevice creates a virtual MFA device on the user's phone.
func (e *Engine) registerPhoneDevice(c Creds, profile, user string) (string, error) {
	serial, seed, err := iamCreateVirtualMFA(c, mfaDeviceName("zsp-phone", user))
	if err != nil {
		return "", err
	}
	e.printf("\nAdd this account to your authenticator app (type the key, or paste the URI into a QR generator you trust):\n")
	e.printf("\n  Account: %s (%s)\n  Key:     %s\n  URI:     otpauth://totp/%s?secret=%s&issuer=%s\n\n",
		profile, user, groupSeed(seed), url.PathEscape("AWS:"+profile+"@"+user), seed, url.QueryEscape("AWS CLI ZSP"))
	zero([]byte(seed))
	c1, err := e.ask("First 6-digit code from the phone: ")
	if err == nil {
		var c2 string
		if c2, err = e.ask("Wait for the NEXT code, enter it:  "); err == nil {
			c1, c2 = strings.TrimSpace(c1), strings.TrimSpace(c2)
			if !validSixDigits(c1) || !validSixDigits(c2) {
				err = errors.New("codes must be 6 digits")
			} else {
				err = iamEnableMFA(c, user, serial, c1, c2)
			}
		}
	}
	if err != nil {
		_ = iamDeleteVirtualMFA(c, serial)
		return "", err
	}
	return serial, nil
}

func twoConsecutiveCodes(seed string, printf func(string, ...any)) (string, string, error) {
	c1, err := totpFresh(seed)
	if err != nil {
		return "", "", err
	}
	wait := time.Duration(30-time.Now().Unix()%30)*time.Second + 300*time.Millisecond
	printf("  waiting %ds for the next code window...\n", int(wait.Seconds()))
	time.Sleep(wait)
	c2, err := totpAt(seed, time.Now())
	return c1, c2, err
}

// MFAEnable: device "pc" makes this PC the MFA device (seed in the vault);
// device "phone" puts the factor on your phone, so every new session needs
// Windows Hello AND a code from the phone (v0.2, recommended for production).
func (e *Engine) MFAEnable(profile, device string, snap *ConfigSnapshot) error {
	if device != "pc" && device != "phone" {
		return errors.New("--device must be pc or phone")
	}
	k, env, err := e.OpenKey(profile, fmt.Sprintf("Turn on MFA (%s) for AWS key '%s'.\nRequested by: %s", device, profile, truncate(e.Caller.Desc, 120)))
	if err != nil {
		return err
	}
	defer k.wipe()
	if m := k.mode(); m != "" {
		if m == device {
			e.printf("MFA (%s) is already on for %s\n", device, profile)
			return nil
		}
		return fmt.Errorf("MFA is already on (%s); run `zsp mfa disable` first", m)
	}
	c := Creds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}
	user, _, err := e.whoAmI(profile, k, c, snap)
	if err != nil {
		return err
	}
	if device == "pc" {
		serial, seed, err := iamCreateVirtualMFA(c, mfaDeviceName("zsp", user))
		if err != nil {
			return err
		}
		c1, c2, err := twoConsecutiveCodes(seed, e.printf)
		if err == nil {
			err = iamEnableMFA(c, user, serial, c1, c2)
		}
		if err != nil {
			_ = iamDeleteVirtualMFA(c, serial)
			e.Audit("mfa-enable", profile, false, err.Error(), e.Caller.Desc)
			return err
		}
		k.MFAMode, k.MFASerial, k.MFASeed = "pc", serial, seed
	} else {
		if k.PhoneSerial == "" {
			serial, err := e.registerPhoneDevice(c, profile, user)
			if err != nil {
				e.Audit("mfa-enable", profile, false, err.Error(), e.Caller.Desc)
				return err
			}
			k.PhoneSerial = serial
		}
		k.MFAMode = "phone"
	}
	if err := e.reseal(profile, k, env.Meta, nil); err != nil {
		return err
	}
	e.clearSessions(profile)
	if _, err := e.adminCreds(profile, k, snap); err != nil { // prove it works before anyone relies on it
		e.Audit("mfa-enable", profile, false, "device enabled but test session failed: "+err.Error(), e.Caller.Desc)
		return fmt.Errorf("MFA device enabled but a test session failed: %w", err)
	}
	e.Audit("mfa-enable", profile, true, device, e.Caller.Desc)
	if device == "pc" {
		e.printf("This PC is now an MFA device for %s. Every session carries MFA, still one Windows Hello.\n", profile)
	} else {
		e.printf("Phone MFA is on for %s: every new session needs Windows Hello AND a code from your phone.\n", profile)
	}
	return nil
}

func (e *Engine) MFADisable(profile string, snap *ConfigSnapshot) error {
	env, err := e.KeyEnvelope(profile)
	if err != nil {
		return err
	}
	if env.Meta["enforced"] == "yes" {
		return errors.New("AWS currently requires MFA for this key; run `zsp mfa unenforce` first or you will lock yourself out")
	}
	if e.hasPhoneCopy(profile) {
		return errors.New("phone approval uses this MFA device; run `zsp phone remove` first")
	}
	k, env, c, user, err := e.openForAdmin(profile, "Turn OFF MFA", snap)
	if err != nil {
		return err
	}
	defer k.wipe()
	if enforced, _ := iamHasUserPolicy(c, user, policyRequireMFA); enforced {
		return errors.New("AWS requires MFA for this key; run `zsp mfa unenforce` first")
	}
	lc := Creds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}
	for _, serial := range []string{k.MFASerial, k.PhoneSerial} {
		if serial == "" {
			continue
		}
		if err := iamDeactivateMFA(c, user, serial); err != nil && !isAWSCode(err, "NoSuchEntity") {
			return err
		}
		_ = iamDeleteVirtualMFA(lc, serial)
	}
	k.MFAMode, k.MFASerial, k.MFASeed, k.PhoneSerial = "", "", "", ""
	e.clearSessions(profile)
	e.Audit("mfa-disable", profile, true, "", e.Caller.Desc)
	return e.reseal(profile, k, env.Meta, map[string]string{"mfa": ""})
}

func requireMFAPolicy() string {
	return `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyEverythingWithoutMFA",
      "Effect": "Deny",
      "NotAction": ["sts:GetSessionToken", "sts:GetCallerIdentity"],
      "Resource": "*",
      "Condition": {"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}
    },
    {
      "Sid": "FreshMFAToCreatePersistentAccess",
      "Effect": "Deny",
      "Action": [
        "iam:CreateAccessKey", "iam:UpdateAccessKey", "iam:CreateVirtualMFADevice", "iam:EnableMFADevice",
        "iam:DeactivateMFADevice", "iam:ResyncMFADevice", "iam:PutUserPolicy", "iam:DeleteUserPolicy",
        "iam:AttachUserPolicy", "iam:DetachUserPolicy", "iam:CreateUser", "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile", "iam:AddUserToGroup", "iam:CreateRole", "iam:UpdateAssumeRolePolicy",
        "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy"
      ],
      "Resource": "*",
      "Condition": {"NumericGreaterThanIfExists": {"aws:MultiFactorAuthAge": "300"}}
    }
  ]
}`
}

func (e *Engine) MFAEnforce(profile string, on bool, snap *ConfigSnapshot) error {
	what := "Make AWS REQUIRE MFA"
	if !on {
		what = "Stop AWS requiring MFA"
	}
	k, env, err := e.OpenKey(profile, fmt.Sprintf("%s for key '%s'.\nRequested by: %s", what, profile, truncate(e.Caller.Desc, 120)))
	if err != nil {
		return err
	}
	defer k.wipe()
	if k.mode() == "" {
		return errors.New("turn on MFA first (zsp mfa enable --device pc|phone)")
	}
	c, err := e.adminCreds(profile, k, snap) // an MFA session must work, or we must not lock MFA in
	if err != nil {
		return fmt.Errorf("refusing: an MFA session did not work (%w)", err)
	}
	user, _, err := e.whoAmI(profile, k, c, snap)
	if err != nil {
		return err
	}
	if on {
		err = iamPutUserPolicy(c, user, policyRequireMFA, requireMFAPolicy())
	} else {
		if e.hasPhoneCopy(profile) {
			return errors.New("remove phone approval first (zsp phone remove): its key copy is only safe while AWS requires MFA")
		}
		err = iamDeleteUserPolicy(c, user, policyRequireMFA)
	}
	if err != nil {
		e.Audit("mfa-enforce", profile, false, err.Error(), e.Caller.Desc)
		return err
	}
	flag := ""
	if on {
		flag = "yes"
	}
	e.Audit("mfa-enforce", profile, true, fmt.Sprintf("require MFA = %v", on), e.Caller.Desc)
	e.printf("AWS requires MFA for %s: %v\n", profile, on)
	return e.reseal(profile, k, env.Meta, map[string]string{"enforced": flag})
}

// Phone approval -----------------------------------------------------------------------------

func (e *Engine) PhoneAdd(profile string, snap *ConfigSnapshot) error {
	k, env, c, user, err := e.openForAdmin(profile, "Add phone approval", snap)
	if err != nil {
		return err
	}
	defer k.wipe()
	// The phone copy opens without Windows Hello. That is only acceptable if AWS
	// refuses the key without a phone code, so verify the policy live in IAM.
	enforced, err := iamHasUserPolicy(c, user, policyRequireMFA)
	if err != nil {
		return err
	}
	if !enforced {
		return errors.New("refusing: AWS does not yet require MFA for this key. Run `zsp mfa enforce` first")
	}
	if k.PhoneSerial == "" {
		serial, err := e.registerPhoneDevice(c, profile, user)
		if err != nil {
			e.Audit("phone-add", profile, false, err.Error(), e.Caller.Desc)
			return err
		}
		k.PhoneSerial = serial
		if err := e.reseal(profile, k, env.Meta, nil); err != nil {
			return err
		}
	}
	if err := e.savePhoneCopy(profile, &PhoneCopy{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey, PhoneSerial: k.PhoneSerial}); err != nil {
		return err
	}
	e.Audit("phone-add", profile, true, k.PhoneSerial, e.Caller.Desc)
	e.printf("Phone approval is on for %s. When nobody is at the PC: zsp approve --profile %s <code>\n", profile, profile)
	return e.updateMeta(profile, map[string]string{"phone": "on", "enforced": "yes"})
}

func (e *Engine) PhoneRemove(profile string, snap *ConfigSnapshot) error {
	if !e.hasPhoneCopy(profile) {
		return errors.New("phone approval is not on for this profile")
	}
	k, env, c, user, err := e.openForAdmin(profile, "Remove phone approval", snap)
	if err != nil {
		return err
	}
	defer k.wipe()
	if err := os.Remove(e.phonePath(profile)); err != nil {
		return err
	}
	if k.PhoneSerial != "" && k.mode() != "phone" {
		if err := iamDeactivateMFA(c, user, k.PhoneSerial); err != nil && !isAWSCode(err, "NoSuchEntity") {
			return err
		}
		_ = iamDeleteVirtualMFA(Creds{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}, k.PhoneSerial)
		k.PhoneSerial = ""
		if err := e.reseal(profile, k, env.Meta, nil); err != nil {
			return err
		}
	}
	e.Audit("phone-remove", profile, true, "", e.Caller.Desc)
	return e.updateMeta(profile, map[string]string{"phone": ""})
}

// Source-IP binding (v0.2) -------------------------------------------------------------------
//
// An inline policy denies everything the user's credentials do from outside
// the given networks. Most infostealers ship tokens to their own servers, so a
// stolen session (or key) stops working there. aws:ViaAWSService keeps calls
// that AWS services make on your behalf (CloudFormation, ...) working. The
// policy-management actions stay allowed so you can always undo it; with
// `mfa enforce` they need fresh MFA, so a thief cannot.

func sourceIPUserPolicy(cidrs []string) string {
	b, _ := json.Marshal(cidrs)
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"DenyOutsideAllowedNetworks","Effect":"Deny","NotAction":["sts:GetCallerIdentity","iam:GetUserPolicy","iam:PutUserPolicy","iam:DeleteUserPolicy","iam:ListUserPolicies"],"Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":%s},"BoolIfExists":{"aws:ViaAWSService":"false"}}}]}`, b)
}

func sourceIPRolePolicy(cidrs []string, user string) string {
	b, _ := json.Marshal(cidrs)
	return fmt.Sprintf(`{"Version":"2012-10-17","Statement":[{"Sid":"DenyZspSessionsOutsideAllowedNetworks","Effect":"Deny","Action":"*","Resource":"*","Condition":{"NotIpAddress":{"aws:SourceIp":%s},"BoolIfExists":{"aws:ViaAWSService":"false"},"StringLike":{"aws:userid":"*:zsp-%s-*"}}}]}`, b, sessionNameBad.ReplaceAllString(user, "-"))
}

func (e *Engine) Netbind(profile string, cidrs []string, force bool, snap *ConfigSnapshot) error {
	off := len(cidrs) == 1 && cidrs[0] == "off"
	if !off {
		ip, err := publicIP()
		if err != nil && !force {
			return fmt.Errorf("could not check this PC's public IP (%v); pass --force to bind anyway", err)
		}
		for _, c := range cidrs {
			if !strings.Contains(c, "/") {
				return fmt.Errorf("%q is not a CIDR (use e.g. 196.25.10.4/32)", c)
			}
		}
		if err == nil && !ipInCIDRs(ip, cidrs) && !force {
			return fmt.Errorf("refusing: this PC's public IP %s is not inside %s, so you would lock yourself out. Add it, or pass --force", ip, strings.Join(cidrs, ", "))
		}
	}
	action := "BIND sessions to " + strings.Join(cidrs, ", ")
	if off {
		action = "REMOVE the source-IP binding"
	}
	k, _, c, user, err := e.openForAdmin(profile, action, snap)
	if err != nil {
		return err
	}
	defer k.wipe()
	var errs []string
	if off {
		if err := iamDeleteUserPolicy(c, user, policySourceIP); err != nil && !isAWSCode(err, "NoSuchEntity") {
			errs = append(errs, "user: "+err.Error())
		}
		for _, r := range e.roles(profile) {
			if err := iamDeleteRolePolicy(c, r, rolePolicyName(policySourceIP, user)); err != nil && !isAWSCode(err, "NoSuchEntity") {
				errs = append(errs, r+": "+err.Error())
			}
		}
	} else {
		if err := iamPutUserPolicy(c, user, policySourceIP, sourceIPUserPolicy(cidrs)); err != nil {
			errs = append(errs, "user: "+err.Error())
		}
		for _, r := range e.roles(profile) {
			if err := iamPutRolePolicy(c, r, rolePolicyName(policySourceIP, user), sourceIPRolePolicy(cidrs, user)); err != nil {
				errs = append(errs, r+": "+err.Error())
			}
		}
	}
	flag := "yes"
	if off {
		flag = ""
	}
	_ = e.updateMeta(profile, map[string]string{"netbind": flag})
	e.Audit("netbind", profile, len(errs) == 0, action+" "+strings.Join(errs, "; "), e.Caller.Desc)
	if len(errs) > 0 {
		return fmt.Errorf("source-IP binding partly failed: %s", strings.Join(errs, "; "))
	}
	if off {
		e.printf("Source-IP binding removed for %s.\n", profile)
	} else {
		e.printf("AWS now refuses %s's credentials from outside %s.\n", profile, strings.Join(cidrs, ", "))
	}
	return nil
}

// Tiers (v0.3) ----------------------------------------------------------------------------------

var roleArnRe = regexp.MustCompile(`^arn:aws[a-z-]*:iam::\d{12}:role/[\w+=,.@/-]+$`)

type TierSpec struct {
	ReadRole, WriteRole, WriteDuration, WriteProfile string
	Verify                                           bool
}

func (e *Engine) TierSet(profile string, t TierSpec, snap *ConfigSnapshot) (*ProfilePolicy, error) {
	if _, err := e.KeyEnvelope(profile); err != nil {
		return nil, err
	}
	for _, r := range []string{t.ReadRole, t.WriteRole} {
		if r != "" && !roleArnRe.MatchString(r) {
			return nil, fmt.Errorf("%q is not an IAM role ARN", r)
		}
	}
	if t.WriteDuration != "" {
		if _, err := parseDurationRange(t.WriteDuration, 15*time.Minute, time.Hour); err != nil {
			return nil, err
		}
	}
	st := e.settings()
	p := st.policyFor(profile)
	np := *p
	if t.ReadRole != "" {
		np.ReadRole = t.ReadRole
	}
	if t.WriteRole != "" {
		np.WriteRole = t.WriteRole
		np.WriteProfile = profile + "-write"
	}
	if t.WriteProfile != "" {
		if _, err := safeProfileName(t.WriteProfile); err != nil {
			return nil, err
		}
		np.WriteProfile = t.WriteProfile
	}
	if t.WriteDuration != "" {
		np.WriteDuration = t.WriteDuration
	}
	if np.ReadRole == "" && np.WriteRole == "" {
		return nil, errors.New("give --read-role and/or --write-role")
	}
	if err := e.approve(profile, fmt.Sprintf("Change access tiers for AWS key '%s':\nread  %s\nwrite %s", profile, orDash(np.ReadRole), orDash(np.WriteRole))); err != nil {
		return nil, err
	}
	if t.Verify {
		k, _, err := e.OpenKey(profile, fmt.Sprintf("Verify the read/write roles for AWS key '%s'.", profile))
		if err != nil {
			return nil, err
		}
		defer k.wipe()
		saved := *p
		*p = np
		_ = e.saveSettings(st) // issue() reads roles from settings
		for _, tier := range []string{tierRead, tierWrite} {
			if (tier == tierRead && np.ReadRole == "") || (tier == tierWrite && np.WriteRole == "") {
				continue
			}
			s, err := e.issue(profile, tier, k, 15*time.Minute, snap, "hello")
			if err != nil {
				*p = saved
				_ = e.saveSettings(st)
				return nil, fmt.Errorf("could not assume the %s role: %w", tier, err)
			}
			e.printf("  %s role OK (session %s)\n", tier, maskKeyID(s.AccessKeyID))
			if tier == tierRead {
				_ = e.Cache.Put(sessionKey(profile, tier), s)
			}
		}
	}
	*p = np
	if err := e.saveSettings(st); err != nil {
		return nil, err
	}
	e.Cache.Remove(profile, func(i *SessionInfo) bool { return i.Tier == tierBase })
	e.Audit("tier-set", profile, true, fmt.Sprintf("read=%s write=%s", orDash(np.ReadRole), orDash(np.WriteRole)), e.Caller.Desc)
	return &np, nil
}

func (e *Engine) TierClear(profile string) (*ProfilePolicy, error) {
	st := e.settings()
	p := st.policyFor(profile)
	old := *p
	if err := e.approve(profile, fmt.Sprintf("REMOVE read/write tiers from AWS key '%s' (sessions get the user's full rights again).", profile)); err != nil {
		return nil, err
	}
	p.ReadRole, p.WriteRole, p.WriteProfile, p.WriteDuration = "", "", "", ""
	if err := e.saveSettings(st); err != nil {
		return nil, err
	}
	e.clearSessions(profile)
	e.Audit("tier-clear", profile, true, "", e.Caller.Desc)
	return &old, nil
}

// Adopt a quarantined key ---------------------------------------------------------------------

func (e *Engine) Adopt(profile string, snap *ConfigSnapshot) error {
	inc, err := readEnvelope(e.incomingPath(profile))
	if err != nil {
		return errors.New("no quarantined key for this profile")
	}
	pt, err := inc.open(e.Guarded, fmt.Sprintf("1/2: open the NEW key %s written to '%s'.", inc.Meta["akid_masked"], profile))
	if err != nil {
		return err
	}
	defer zero(pt)
	var nk KeyPayload
	if err := json.Unmarshal(pt, &nk); err != nil {
		return err
	}
	defer nk.wipe()
	old, env, err := e.OpenKey(profile, fmt.Sprintf("2/2: replace the sealed key for '%s' (MFA settings are kept).", profile))
	if err != nil {
		return err
	}
	defer old.wipe()
	pin, err := e.LoadPin(profile)
	if err != nil {
		return err
	}
	id, err := getCallerIdentity(Creds{AccessKeyID: nk.AccessKeyID, SecretAccessKey: nk.SecretAccessKey}, regionFromConfig(snap, profile))
	if err != nil {
		return fmt.Errorf("new key does not work: %w", err)
	}
	if pin != nil && (pin.Account != id.Account || pin.Arn != id.Arn) {
		e.Audit("adopt", profile, false, "new key belongs to "+shortArn(id.Arn), e.Caller.Desc)
		return fmt.Errorf("REFUSED: new key belongs to %s (%s), profile is pinned to %s", maskAccount(id.Account), shortArn(id.Arn), shortArn(pin.Arn))
	}
	old.AccessKeyID, old.SecretAccessKey = nk.AccessKeyID, nk.SecretAccessKey
	if err := e.reseal(profile, old, env.Meta, nil); err != nil {
		return err
	}
	if pc, err := e.loadPhoneCopy(profile); err == nil {
		pc.AccessKeyID, pc.SecretAccessKey = nk.AccessKeyID, nk.SecretAccessKey
		if err := e.savePhoneCopy(profile, pc); err != nil {
			return err
		}
	}
	os.Remove(e.incomingPath(profile))
	e.clearSessions(profile)
	e.Audit("adopt", profile, true, "now "+maskKeyID(nk.AccessKeyID), e.Caller.Desc)
	e.printf("Adopted the new key for %s\n", profile)
	return nil
}

// Restore to plain text ---------------------------------------------------------------------------

// Restore hands the long-lived key back (the client writes it to ~/.aws) and
// removes it from the vault. Hello-gated.
func (e *Engine) Restore(profile string, force bool) (*KeyPayload, error) {
	env, err := e.KeyEnvelope(profile)
	if err != nil {
		return nil, err
	}
	if env.Meta["enforced"] == "yes" && !force {
		return nil, fmt.Errorf("AWS requires MFA for '%s'; a plain-text key would be useless without the MFA device. Run `zsp mfa unenforce --profile %s` first (or pass --force)", profile, profile)
	}
	k, _, err := e.OpenKey(profile, fmt.Sprintf("Put AWS key '%s' BACK into ~/.aws/credentials as plain text.\nRequested by: %s", profile, truncate(e.Caller.Desc, 120)))
	if err != nil {
		return nil, err
	}
	st := e.settings()
	if !st.isKept(profile) {
		st.Keep = append(st.Keep, profile) // or the watcher would move it straight back
	}
	delete(st.Profiles, profile)
	_ = e.saveSettings(st)
	for _, p := range []string{e.keyPath(profile), e.phonePath(profile), e.pinPath(profile), e.incomingPath(profile)} {
		os.Remove(p)
	}
	e.clearSessions(profile)
	e.forgetCallers(profile)
	e.Audit("restored-plaintext", profile, true, maskKeyID(k.AccessKeyID), e.Caller.Desc)
	return &KeyPayload{AccessKeyID: k.AccessKeyID, SecretAccessKey: k.SecretAccessKey}, nil
}

func (e *Engine) PinReset(profile string) error {
	if err := e.approve(profile, fmt.Sprintf("Reset the account pin for AWS profile '%s'. The next session pins it again.", profile)); err != nil {
		return err
	}
	os.Remove(e.pinPath(profile))
	e.clearSessions(profile)
	e.Audit("pin-reset", profile, true, "", e.Caller.Desc)
	e.printf("pin cleared; the next session will ask you to pin the account again\n")
	return nil
}
