//go:build !windows

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- Known-answer tests ------------------------------------------------------------------

// AWS documentation SigV4 example: GET iam ListUsers, 2015-08-30T12:36:00Z.
func TestSigV4IAMExample(t *testing.T) {
	c := Creds{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	if got := fmt.Sprintf("%x", signingKey(c.SecretAccessKey, "20150830", "us-east-1", "iam")); got != "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9" {
		t.Fatalf("signing key %s", got)
	}
	now, _ := time.Parse("20060102T150405Z", "20150830T123600Z")
	auth := signRequest(c, "GET", "/", url.Values{"Action": {"ListUsers"}, "Version": {"2010-05-08"}},
		map[string]string{"Host": "iam.amazonaws.com", "Content-Type": "application/x-www-form-urlencoded; charset=utf-8", "X-Amz-Date": "20150830T123600Z"},
		nil, "us-east-1", "iam", now)
	if !strings.HasSuffix(auth, "Signature=5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7") {
		t.Fatalf("auth header %s", auth)
	}
}

// AWS S3 documentation example: GET /test.txt with a Range header.
func TestSigV4S3Example(t *testing.T) {
	c := Creds{AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	now, _ := time.Parse("20060102T150405Z", "20130524T000000Z")
	auth := signRequest(c, "GET", "/test.txt", nil, map[string]string{
		"host": "examplebucket.s3.amazonaws.com", "range": "bytes=0-9",
		"x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"x-amz-date":           "20130524T000000Z",
	}, nil, "us-east-1", "s3", now)
	if !strings.HasSuffix(auth, "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Fatalf("auth header %s", auth)
	}
}

// RFC 6238 appendix B (SHA-1), truncated to 6 digits as AWS uses.
func TestTOTPRFC6238(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for ts, want := range map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"} {
		if got, err := totpAt(seed, time.Unix(ts, 0)); err != nil || got != want {
			t.Fatalf("t=%d got %s want %s (%v)", ts, got, want, err)
		}
	}
}

func TestINIRoundTripAndEdit(t *testing.T) {
	in := "# my keys\r\n[default]\r\naws_access_key_id = AKIAAAAAAAAAAAAAAAAA\r\naws_secret_access_key = s3cr3t\r\n\r\n[keep]\r\nfoo = bar ; comment\r\n"
	f := parseINI(in)
	if f.String() != in {
		t.Fatalf("round trip changed file:\n%q", f.String())
	}
	f.section("default").del("aws_access_key_id", "aws_secret_access_key")
	f.removeSection("default")
	f.ensureSection("profile new").set("credential_process", `"C:\x y\zsp.exe" credential-process --profile new`)
	out := f.String()
	if strings.Contains(out, "s3cr3t") || !strings.Contains(out, "# my keys") || !strings.Contains(out, "\r\n[profile new]\r\n") {
		t.Fatalf("bad edit:\n%s", out)
	}
}

func TestCallerIdentityRules(t *testing.T) {
	aws := CallerInfo{Image: `C:\Program Files\Amazon\AWSCLIV2\aws.exe`, Args: []string{"aws", "--profile", "p", "configure", "export-credentials"}, Signed: true}
	if id, always, _ := aws.identity(); always || id != strings.ToLower(aws.Image) {
		t.Fatal("signed aws.exe should be remembered by path")
	}
	if aws.sensitiveCommand(defaultSensitiveCommands) != "configure export-credentials" {
		t.Fatal("export-credentials not flagged")
	}
	if (CallerInfo{Args: []string{"aws", "s3", "ls"}}).sensitiveCommand(defaultSensitiveCommands) != "" {
		t.Fatal("s3 ls flagged")
	}
	py := CallerInfo{Image: `C:\Python312\python.exe`, Args: []string{"python", "-u", "deploy.py"}, Hash: "abc"}
	if id, always, _ := py.identity(); always || !strings.HasSuffix(id, "|deploy.py") || !strings.Contains(id, "#abc") {
		t.Fatalf("python script identity: %s", id)
	}
	if _, always, _ := (CallerInfo{Image: `C:\x\pwsh.exe`, Args: []string{"pwsh", "-Command", "x"}}).identity(); !always {
		t.Fatal("pwsh -Command must always ask")
	}
}

func TestGuardAnalysis(t *testing.T) {
	snap := &ConfigSnapshot{Exe: "/opt/zsp/zsp", Env: map[string]string{"HTTPS_PROXY": "http://proxy:8080"}, Config: `
[profile prod]
credential_process = /opt/zsp/zsp credential-process --profile prod
region = af-south-1
[profile other]
credential_process = /tmp/evil credential-process --profile other
[profile prod2]
credential_process = /tmp/evil credential-process --profile prod2
role_arn = arn:aws:iam::1:role/x
[services corp]
s3 =
  endpoint_url = https://evil.example
`}
	got := map[string]bool{}
	for _, f := range analyzeConfig(snap, []string{"prod", "prod2"}, snap.Exe) {
		got[f.Key] = true
	}
	for _, want := range []string{"env:HTTPS_PROXY", "config:[profile prod2].credential_process", "config:[profile prod2].role_arn", "config:[services corp].endpoint_url"} {
		if !got[want] {
			t.Errorf("missing finding %s (got %v)", want, got)
		}
	}
	if got["config:[profile prod].credential_process"] || got["config:[profile other].credential_process"] {
		t.Errorf("false positive: %v", got)
	}
}

// ---- harness -------------------------------------------------------------------------------

type testUI struct {
	answers []string
	out     strings.Builder
}

func (u *testUI) Printf(f string, a ...any) { fmt.Fprintf(&u.out, f, a...) }
func (u *testUI) Ask(string) (string, error) {
	if len(u.answers) == 0 {
		return "", fmt.Errorf("unexpected question")
	}
	a := u.answers[0]
	u.answers = u.answers[1:]
	return a, nil
}
func (u *testUI) HelloUnwrap(b []byte, p string) ([]byte, error) { return localHelloUnwrap(b, p) }

const testExe = "/opt/zsp/zsp"

func setupHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	for k, v := range map[string]string{"HOME": home, "USERPROFILE": home, "ZSP_HOME": filepath.Join(home, "vault"), "ZSP_INSECURE_DEV": "1",
		"AWS_SHARED_CREDENTIALS_FILE": "", "AWS_CONFIG_FILE": "", "AWS_PROFILE": "", "HTTPS_PROXY": "", "HTTP_PROXY": "", "https_proxy": "",
		"ZSP_TEST_LOCKED": "", "ZSP_TEST_IDLE": "", "ZSP_STS_REGION": ""} {
		t.Setenv(k, v)
	}
	for _, kv := range os.Environ() { // this sandbox's own proxy/CA settings would (rightly) trip the guard
		if k := strings.SplitN(kv, "=", 2)[0]; guardedEnvName(k) {
			t.Setenv(k, "")
			os.Unsetenv(k)
		}
	}
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("HTTP_PROXY")
	os.Unsetenv("https_proxy")
	devPrompts, devDeclineHello = nil, false
	cliExeOverride = testExe
	t.Cleanup(func() { cliExeOverride = "" })
	os.MkdirAll(filepath.Join(home, ".aws"), 0o700)
}

func writeAWS(t *testing.T, cred, cfg string) {
	t.Helper()
	os.WriteFile(credentialsFile(), []byte(cred), 0o600)
	os.WriteFile(configFile(), []byte(cfg), 0o600)
}

var awsCaller = CallerInfo{Desc: "aws s3 ls ← pwsh", Image: "/usr/bin/aws", Args: []string{"aws", "s3", "ls"}, Signed: true}

func cred(b Backend, profile, tier string, c CallerInfo) (*Session, error) {
	r, err := b.Do(&Request{Op: "credential", Profile: profile, Tier: tier, Snap: buildSnapshot(), Caller: c})
	if err != nil {
		return nil, err
	}
	return r.Session, nil
}

func userBackend(t *testing.T) (*localBackend, *testUI) {
	t.Helper()
	e, err := openUserEngine(true)
	if err != nil {
		t.Fatal(err)
	}
	ui := &testUI{}
	return &localBackend{e: e, ui: ui}, ui
}

const (
	richardArn = "arn:aws:iam::111122223333:user/richard"
	readRole   = "arn:aws:iam::111122223333:role/zsp-read"
	writeRole  = "arn:aws:iam::111122223333:role/zsp-write"
)

// ---- user mode ---------------------------------------------------------------------------------

func TestUserModeLifecycle(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	aws.keys["AKIABEDROCK000000001"] = fakeUser{"111122223333", richardArn}
	writeAWS(t,
		"[bedrock]\naws_access_key_id = AKIABEDROCK000000001\naws_secret_access_key = SECRETbedrock\n\n"+
			"[personal]\naws_access_key_id = AKIAPERSONAL00000001\naws_secret_access_key = SECRETpersonal\n\n"+
			"[temp]\naws_access_key_id = ASIATEMP\naws_secret_access_key = x\naws_session_token = y\n",
		"[profile bedrock]\nregion = af-south-1\n")
	b, _ := userBackend(t)
	if _, err := b.Do(&Request{Op: "setting", Args: map[string]string{"name": "keep", "value": "personal"}}); err != nil {
		t.Fatal(err)
	}
	if len(devPrompts) != 0 {
		t.Fatal("settings on an empty vault should not prompt")
	}
	sd, _ := statusOf(b)
	res, err := importKeys(b, nil, sd.Settings, "test")
	if err != nil || len(res.Moved) != 1 || res.Moved[0] != "bedrock" {
		t.Fatalf("import %+v %v", res, err)
	}
	credText, _ := os.ReadFile(credentialsFile())
	if strings.Contains(string(credText), "SECRETbedrock") || !strings.Contains(string(credText), "SECRETpersonal") || !strings.Contains(string(credText), "aws_session_token") {
		t.Fatalf("credentials after import:\n%s", credText)
	}
	cfg, _ := os.ReadFile(configFile())
	if !strings.Contains(string(cfg), testExe+" credential-process --profile bedrock") || !strings.Contains(string(cfg), "region = af-south-1") {
		t.Fatalf("config after import:\n%s", cfg)
	}
	raw, _ := os.ReadFile(b.e.keyPath("bedrock"))
	if strings.Contains(string(raw), "SECRETbedrock") || strings.Contains(string(raw), "AKIABEDROCK") {
		t.Fatal("sealed file leaks the key")
	}
	if len(devPrompts) != 0 {
		t.Fatal("moving a key in must not prompt")
	}

	// First session: Hello names key, length and caller; then the pin is signed.
	s, err := cred(b, "bedrock", "", awsCaller)
	if err != nil {
		t.Fatal(err)
	}
	if len(devPrompts) != 2 || !strings.Contains(devPrompts[0], "'bedrock'") || !strings.Contains(devPrompts[0], "1-hour") || !strings.Contains(devPrompts[0], "aws s3 ls") || !strings.Contains(devPrompts[1], "Pin AWS profile") {
		t.Fatalf("prompts %q", devPrompts)
	}
	var out map[string]any
	if err := json.Unmarshal(credentialProcessJSON(s), &out); err != nil || out["Version"].(float64) != 1 {
		t.Fatalf("credential_process JSON %v", out)
	}

	// Cached: no prompt, no STS call.
	before := aws.calls["GetSessionToken"]
	if _, err := cred(b, "bedrock", "", awsCaller); err != nil || len(devPrompts) != 2 || aws.calls["GetSessionToken"] != before {
		t.Fatalf("expected cached session: %v prompts=%d", err, len(devPrompts))
	}

	// v0.2 presence on reuse.
	t.Setenv("ZSP_TEST_LOCKED", "1")
	if _, err := cred(b, "bedrock", "", awsCaller); err == nil || !strings.Contains(err.Error(), "not handed out") {
		t.Fatalf("locked: %v", err)
	}
	t.Setenv("ZSP_TEST_LOCKED", "")
	t.Setenv("ZSP_TEST_IDLE", "45m")
	if _, err := cred(b, "bedrock", "", awsCaller); err == nil {
		t.Fatal("idle 45m should withhold the cached session")
	}
	t.Setenv("ZSP_TEST_IDLE", "10m")
	if _, err := cred(b, "bedrock", "", awsCaller); err != nil {
		t.Fatalf("idle 10m: %v", err)
	}
	t.Setenv("ZSP_TEST_IDLE", "")

	// Sensitive command: always a fresh approval, even with a session cached.
	exp := CallerInfo{Desc: "aws configure export-credentials", Image: "/usr/bin/aws", Args: []string{"aws", "configure", "export-credentials", "--profile", "bedrock"}}
	n := len(devPrompts)
	if _, err := cred(b, "bedrock", "", exp); err != nil || len(devPrompts) != n+1 || !strings.Contains(devPrompts[n], "PRINT or MINT") {
		t.Fatalf("sensitive approval: %v %q", err, devPrompts[n:])
	}
	devDeclineHello = true
	if _, err := cred(b, "bedrock", "", exp); err == nil {
		t.Fatal("declined export-credentials still got a session")
	}
	devDeclineHello = false

	// Lock event clears Hello sessions.
	if r, err := b.Do(&Request{Op: "lock-clear"}); err != nil || r.Text != "1" {
		t.Fatalf("lock-clear %v %v", r, err)
	}
	n = len(devPrompts)
	if _, err := cred(b, "bedrock", "", awsCaller); err != nil || len(devPrompts) != n+1 {
		t.Fatalf("after lock a new Hello is needed: %v", err)
	}

	// Config guard: an endpoint_url appears -> refused until approved.
	os.WriteFile(configFile(), append(cfg, []byte("[default]\nendpoint_url = https://collector.evil\n")...), 0o600)
	if _, err := cred(b, "bedrock", "", awsCaller); err == nil || !strings.Contains(err.Error(), "endpoint_url") {
		t.Fatalf("guard: %v", err)
	}
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:8080")
	if _, err := b.Do(&Request{Op: "guard-approve", Snap: buildSnapshot()}); err != nil {
		t.Fatal(err)
	}
	if _, err := cred(b, "bedrock", "", awsCaller); err != nil {
		t.Fatalf("after approve: %v", err)
	}
	t.Setenv("HTTPS_PROXY", "http://other:3128")
	if _, err := cred(b, "bedrock", "", awsCaller); err == nil || !strings.Contains(err.Error(), "HTTPS_PROXY") {
		t.Fatalf("changed proxy not caught: %v", err)
	}
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:8080")

	// Malware seals ITS key under our profile name: the account pin refuses it.
	aws.keys["AKIAATTACKER00000001"] = fakeUser{"999988887777", "arn:aws:iam::999988887777:user/evil"}
	b.e.clearSessions("bedrock")
	if err := b.e.SealKey("bedrock", &KeyPayload{AccessKeyID: "AKIAATTACKER00000001", SecretAccessKey: "x"}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := cred(b, "bedrock", "", awsCaller); err == nil || !strings.Contains(err.Error(), "REFUSED") {
		t.Fatalf("swapped key not refused: %v", err)
	}

	// Audit: intact and names callers; truncation and edits are detected.
	if r, err := b.Do(&Request{Op: "audit-verify"}); err != nil {
		t.Fatalf("audit %v %v", r, err)
	}
	ab, _ := os.ReadFile(b.e.auditPath())
	for _, want := range []string{"aws s3 ls ← pwsh", "pin-mismatch", "guard-refused", "session-withheld", "sensitive-declined"} {
		if !strings.Contains(string(ab), want) {
			t.Errorf("audit lacks %q", want)
		}
	}
	lines := strings.Split(strings.TrimSpace(string(ab)), "\n")
	os.WriteFile(b.e.auditPath(), []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600)
	if _, err := b.Do(&Request{Op: "audit-verify"}); err == nil {
		t.Fatal("truncation not detected")
	}
	os.WriteFile(b.e.auditPath(), []byte(strings.Replace(string(ab), `"session-used"`, `"session-usex"`, 1)), 0o600)
	if _, err := b.Do(&Request{Op: "audit-verify"}); err == nil {
		t.Fatal("edit not detected")
	}
}

func TestSettingsNeedHello(t *testing.T) {
	setupHome(t)
	newFakeAWS(t)
	b, _ := userBackend(t)
	b.e.SealKey("p", &KeyPayload{AccessKeyID: "AKIAPPPPPPPPPPPPPPP1", SecretAccessKey: "x"}, nil)
	devDeclineHello = true
	if _, err := b.Do(&Request{Op: "setting", Args: map[string]string{"name": "reuse-presence", "value": "off"}}); err == nil {
		t.Fatal("weakening a setting without Hello succeeded")
	}
	if b.e.settings().ReusePresence != "lock+idle" {
		t.Fatal("setting changed although Hello was declined")
	}
	devDeclineHello = false
	if _, err := b.Do(&Request{Op: "setting", Args: map[string]string{"name": "reuse-presence", "value": "lock"}}); err != nil || b.e.settings().ReusePresence != "lock" {
		t.Fatalf("approved setting: %v", err)
	}
}

func TestTiersAndScopedRevoke(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	aws.keys["AKIATIER000000000001"] = fakeUser{"111122223333", richardArn}
	aws.roles[readRole], aws.roles[writeRole] = true, true
	writeAWS(t, "", "[profile prod]\nregion = eu-west-1\n")
	b, _ := userBackend(t)
	b.e.SealKey("prod", &KeyPayload{AccessKeyID: "AKIATIER000000000001", SecretAccessKey: "x"}, nil)
	scrubAndWire(map[string]bool{"prod": true})

	resp, err := b.Do(&Request{Op: "tier-set", Profile: "prod", Snap: buildSnapshot(), Args: map[string]string{"read": readRole, "write": writeRole, "verify": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	var pol ProfilePolicy
	json.Unmarshal(resp.Data, &pol)
	if pol.WriteProfile != "prod-write" {
		t.Fatalf("policy %+v", pol)
	}
	if err := wireWriteProfile("prod", pol.WriteProfile); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(configFile())
	if !strings.Contains(string(cfg), "[profile prod-write]") || !strings.Contains(string(cfg), "--tier write") || strings.Count(string(cfg), "region = eu-west-1") != 2 {
		t.Fatalf("write profile wiring:\n%s", cfg)
	}

	// Read tier: cached by verify, an AssumeRole session named for zsp.
	s, err := cred(b, "prod", "", awsCaller)
	if err != nil || s.Tier != tierRead {
		t.Fatalf("read tier %v %+v", err, s)
	}
	// Write tier: fresh Hello, 15 minutes, write role, scoped session name.
	n := len(devPrompts)
	s, err = cred(b, "prod", tierWrite, awsCaller)
	if err != nil || s.Tier != tierWrite || len(devPrompts) != n+1 || !strings.Contains(devPrompts[n], "WRITE") {
		t.Fatalf("write tier %v %+v %q", err, s, devPrompts[n:])
	}
	if aws.lastAssume["RoleArn"] != writeRole || aws.lastAssume["RoleSessionName"] != "zsp-richard-prod-w" || aws.lastAssume["DurationSeconds"] != "900" {
		t.Fatalf("assume %v", aws.lastAssume)
	}
	// Reused while present, without a new prompt.
	if _, err := cred(b, "prod", tierWrite, awsCaller); err != nil || len(devPrompts) != n+1 {
		t.Fatalf("write reuse: %v", err)
	}

	// Revoke: user policy + role policies scoped to this user's zsp sessions.
	if _, err := b.Do(&Request{Op: "revoke", Profile: "prod", Snap: buildSnapshot()}); err != nil {
		t.Fatal(err)
	}
	if aws.userPols["richard"][policyRevoke] == "" {
		t.Fatal("user revoke policy missing")
	}
	rp := aws.rolePols["zsp-write"]["aws-cli-zsp-revoke-older-sessions-richard"]
	if !strings.Contains(rp, `"aws:userid":"*:zsp-richard-*"`) || !strings.Contains(rp, "aws:TokenIssueTime") {
		t.Fatalf("role revoke policy %s", rp)
	}
	if ss, _ := b.e.Cache.Get(sessionKey("prod", tierWrite), 0); ss != nil {
		t.Fatal("revoke left a cached session")
	}
}

func TestPhoneOnlyMFA(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	seed := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	serial := "arn:aws:iam::111122223333:mfa/zsp-phone-richard"
	aws.keys["AKIAPHONEONLY0000001"] = fakeUser{"111122223333", richardArn}
	aws.mfaSeed[serial] = seed
	writeAWS(t, "", "")
	b, ui := userBackend(t)
	k := &KeyPayload{AccessKeyID: "AKIAPHONEONLY0000001", SecretAccessKey: "x", MFAMode: "phone", PhoneSerial: serial}
	b.e.SealKey("prod", k, keyMeta(k, nil))

	ui.answers = []string{"000000"}
	if _, err := cred(b, "prod", "", awsCaller); err == nil {
		t.Fatal("wrong phone code accepted")
	}
	code, _ := totpAt(seed, time.Now())
	ui.answers = []string{code}
	s, err := cred(b, "prod", "", awsCaller)
	if err != nil || !s.MFA {
		t.Fatalf("phone-only session %v %+v", err, s)
	}
}

func TestPhoneApprovalNeedsCode(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	seed := "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	phone := "arn:aws:iam::111122223333:mfa/zsp-phone-richard"
	aws.keys["AKIAPHONEUSER0000001"] = fakeUser{"111122223333", richardArn}
	aws.mfaSeed[phone] = seed
	writeAWS(t, "", "")
	b, _ := userBackend(t)
	k := &KeyPayload{AccessKeyID: "AKIAPHONEUSER0000001", SecretAccessKey: "x"}
	b.e.SealKey("ops", k, nil)
	if _, err := cred(b, "ops", "", awsCaller); err != nil { // pins the account at the PC
		t.Fatal(err)
	}
	b.e.clearSessions("ops")
	b.e.savePhoneCopy("ops", &PhoneCopy{AccessKeyID: k.AccessKeyID, SecretAccessKey: "x", PhoneSerial: phone})

	// Nobody at the PC: fail fast with instructions, no prompt.
	t.Setenv("ZSP_TEST_LOCKED", "1")
	n := len(devPrompts)
	if _, err := cred(b, "ops", "", awsCaller); err == nil || !strings.Contains(err.Error(), "zsp approve --profile ops") || len(devPrompts) != n {
		t.Fatalf("absent: %v", err)
	}
	if _, err := b.Do(&Request{Op: "approve", Profile: "ops", Args: map[string]string{"code": "000000"}, Snap: buildSnapshot()}); err == nil {
		t.Fatal("wrong code accepted")
	}
	code, _ := totpAt(seed, time.Now())
	if _, err := b.Do(&Request{Op: "approve", Profile: "ops", Args: map[string]string{"code": code}, Snap: buildSnapshot()}); err != nil {
		t.Fatal(err)
	}
	// The phone-approved session is served while the PC stays locked.
	if s, err := cred(b, "ops", "", awsCaller); err != nil || s.Source != "phone" {
		t.Fatalf("phone session while locked: %v", err)
	}
}

func TestNetbindRefusesLockout(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	aws.keys["AKIANETBIND000000001"] = fakeUser{"111122223333", richardArn}
	writeAWS(t, "", "")
	b, _ := userBackend(t)
	b.e.SealKey("p", &KeyPayload{AccessKeyID: "AKIANETBIND000000001", SecretAccessKey: "x"}, nil)
	if _, err := b.Do(&Request{Op: "netbind", Profile: "p", Args: map[string]string{"cidrs": "10.0.0.0/8"}, Snap: buildSnapshot()}); err == nil || !strings.Contains(err.Error(), "lock yourself out") {
		t.Fatalf("lockout not refused: %v", err)
	}
	if _, err := b.Do(&Request{Op: "netbind", Profile: "p", Args: map[string]string{"cidrs": "196.25.1.0/24"}, Snap: buildSnapshot()}); err != nil {
		t.Fatal(err)
	}
	pol := aws.userPols["richard"][policySourceIP]
	if !strings.Contains(pol, `"196.25.1.0/24"`) || !strings.Contains(pol, "aws:ViaAWSService") {
		t.Fatalf("policy %s", pol)
	}
	if _, err := b.Do(&Request{Op: "netbind", Profile: "p", Args: map[string]string{"cidrs": "off"}, Snap: buildSnapshot()}); err != nil || aws.userPols["richard"][policySourceIP] != "" {
		t.Fatalf("off: %v", err)
	}
}

func TestAuditShippingAndTamperAlert(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	aws.keys["AKIASHIP000000000001"] = fakeUser{"111122223333", richardArn}
	writeAWS(t, "", "")
	b, _ := userBackend(t)
	b.e.Label = "richard"
	if _, err := b.Do(&Request{Op: "ship-setup", Args: map[string]string{"bucket": "zsp-audit", "region": "af-south-1", "prefix": "zsp",
		"akid": "AKIASHIPPERKEY000001", "secret": "abcdefghijklmnopqrstuvwxyz0123456789ABCD"}}); err != nil {
		t.Fatal(err)
	}
	b.e.Audit("session-refused", "p", false, "test refusal", "x") // refusals ship at once
	var shipped string
	for k, v := range aws.objects {
		if strings.HasSuffix(k, ".jsonl") && strings.Contains(string(v), "test refusal") {
			shipped = k
		}
	}
	if shipped == "" || !strings.HasPrefix(shipped, "zsp-audit/zsp/") && !strings.Contains(shipped, "/richard/") {
		t.Fatalf("no shipped object with the refusal: %v", keysOf(aws.objects))
	}
	// Edit an already-shipped line locally: the next ship raises a TAMPER object.
	ab, _ := os.ReadFile(b.e.auditPath())
	os.WriteFile(b.e.auditPath(), []byte(strings.Replace(string(ab), "test refusal", "nothing here", 1)), 0o600)
	b.e.Audit("x", "", true, "", "")
	b.Do(&Request{Op: "ship-now"})
	found := false
	for k := range aws.objects {
		if strings.HasSuffix(k, "-TAMPER.json") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no tamper alert: %v", keysOf(aws.objects))
	}
}

func keysOf(m map[string][]byte) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---- service mode (broker) ------------------------------------------------------------------------

func svcDo(b *Broker, id PeerIdentity, req *Request, ui UI) (*Response, error) {
	// A buffered loopback socket, like the 64 KB-buffered named pipe on Windows
	// (net.Pipe is unbuffered and would not model it).
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	go func() {
		s, err := ln.Accept()
		if err != nil {
			return
		}
		serveConn(s, func(r *Request, rui UI) (*Response, error) { return b.Handle(id, r, rui) })
		s.Close()
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if req.Snap == nil {
		req.Snap = buildSnapshot()
	}
	return clientRoundTrip(c, req, ui)
}

func newTestBroker(t *testing.T) (*Broker, PeerIdentity) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "programdata")
	qk := swKey{filepath.Join(root, "..", "svc-quiet.pem")}
	if _, err := qk.load(true); err != nil {
		t.Fatal(err)
	}
	b := NewBroker(root, &swSealer{name: "svc-tpm", k: qk})
	id := PeerIdentity{SID: "S-1-5-21-111-222-333-1001", User: `PC\richard`, OSSession: 1, ClientTrusted: true, ClientImage: "zsp.exe", Caller: awsCaller}
	return b, id
}

func TestBrokerSplitKeyAndPolicies(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	aws.keys["AKIASERVICE000000001"] = fakeUser{"111122223333", richardArn}
	writeAWS(t, "", "[profile bedrock]\nregion = af-south-1\n")
	b, id := newTestBroker(t)
	ui := &testUI{}

	if _, err := svcDo(b, id, &Request{Op: "credential", Profile: "bedrock"}, ui); err == nil || !strings.Contains(err.Error(), "not enrolled") {
		t.Fatalf("unenrolled: %v", err)
	}
	pub, err := localHelloPublicKey(true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svcDo(b, id, &Request{Op: "enroll", Args: map[string]string{"pub": encodePublicKey(pub)}}, ui); err != nil {
		t.Fatal(err)
	}
	if _, err := svcDo(b, id, &Request{Op: "seal", Profile: "bedrock", Key: &KeyPayload{AccessKeyID: "AKIASERVICE000000001", SecretAccessKey: "SECRETsvc"}}, ui); err != nil {
		t.Fatal(err)
	}
	if len(devPrompts) != 0 {
		t.Fatal("sealing into the service must not prompt")
	}

	// Credential: the broker asks the client for a Hello unwrap of K1.
	s, err := svcDo(b, id, &Request{Op: "credential", Profile: "bedrock"}, ui)
	if err != nil || s.Session == nil {
		t.Fatalf("credential %v", err)
	}
	if len(devPrompts) != 1 || !strings.Contains(devPrompts[0], "aws s3 ls") {
		t.Fatalf("prompts %q", devPrompts)
	}
	if files, _ := filepath.Glob(filepath.Join(b.Root, "users", id.SID, "sessions", "*")); len(files) != 0 {
		t.Fatalf("service sessions must never touch disk: %v", files)
	}
	if _, err := svcDo(b, id, &Request{Op: "credential", Profile: "bedrock"}, ui); err != nil || len(devPrompts) != 1 {
		t.Fatalf("cached: %v %d", err, len(devPrompts))
	}

	// Split key: neither half opens the envelope.
	env, _ := readEnvelope(filepath.Join(b.Root, "users", id.SID, "keys", "bedrock.sealed"))
	var sb splitBlob
	json.Unmarshal(env.Wrapped, &sb)
	k1, err := localHelloUnwrap(sb.K1, "test")
	if err != nil {
		t.Fatal(err)
	}
	fake := &Envelope{V: 1, Kind: env.Kind, Purpose: env.Purpose, Profile: env.Profile, Nonce: env.Nonce, CT: env.CT, Wrapped: sb.K1}
	if _, err := fake.open(constSealer(k1), ""); err == nil {
		t.Fatal("the user's half alone opened the key")
	}
	k2, _ := b.Quiet.Unwrap(sb.K2, "")
	if _, err := fake.open(constSealer(k2), ""); err == nil {
		t.Fatal("the service's half alone opened the key")
	}

	// A new program needs one approval; it is then remembered.
	py := CallerInfo{Desc: "python deploy.py", Image: "/usr/bin/python3", Args: []string{"python3", "deploy.py"}, Hash: "h1"}
	pid := id
	pid.Caller = py
	n := len(devPrompts)
	if _, err := svcDo(b, pid, &Request{Op: "credential", Profile: "bedrock"}, ui); err != nil || len(devPrompts) != n+1 || !strings.Contains(devPrompts[n], "has not used this key") {
		t.Fatalf("new caller: %v %q", err, devPrompts[n:])
	}
	if _, err := svcDo(b, pid, &Request{Op: "credential", Profile: "bedrock"}, ui); err != nil || len(devPrompts) != n+1 {
		t.Fatalf("remembered caller asked again: %v", err)
	}
	// Inline code is never remembered.
	pid.Caller = CallerInfo{Desc: "python -c ...", Image: "/usr/bin/python3", Args: []string{"python3", "-c", "import boto3"}}
	svcDo(b, pid, &Request{Op: "credential", Profile: "bedrock"}, ui)
	svcDo(b, pid, &Request{Op: "credential", Profile: "bedrock"}, ui)
	if len(devPrompts) != n+3 {
		t.Fatalf("inline python should ask every time: %d", len(devPrompts)-n)
	}
	devDeclineHello = true
	if _, err := svcDo(b, pid, &Request{Op: "credential", Profile: "bedrock"}, ui); err == nil {
		t.Fatal("declined inline caller got credentials")
	}
	devDeclineHello = false

	// Lock state comes from the broker (WTS), not from the client.
	locked := true
	b.Lock = func(uint32) (bool, bool) { return locked, true }
	if _, err := svcDo(b, id, &Request{Op: "credential", Profile: "bedrock"}, ui); err == nil {
		t.Fatal("cached session handed out while the session is locked")
	}
	b.OnLock(1)
	locked = false
	n = len(devPrompts)
	if _, err := svcDo(b, id, &Request{Op: "credential", Profile: "bedrock"}, ui); err != nil || len(devPrompts) != n+1 {
		t.Fatalf("after lock event a new Hello is needed: %v", err)
	}

	// Only the installed zsp.exe may talk to the broker.
	bad := id
	bad.ClientTrusted, bad.ClientImage = false, `C:\Users\x\evil.exe`
	if _, err := svcDo(b, bad, &Request{Op: "credential", Profile: "bedrock"}, ui); err == nil || !strings.Contains(err.Error(), "only the installed zsp.exe") {
		t.Fatalf("untrusted client: %v", err)
	}

	// Another Hello key cannot re-enrol over a vault with keys in it.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := svcDo(b, id, &Request{Op: "enroll", Args: map[string]string{"pub": encodePublicKey(&other.PublicKey)}}, ui); err == nil {
		t.Fatal("re-enrolment with a different key accepted")
	}

	// Another Windows user sees an empty, separate vault.
	id2 := id
	id2.SID = "S-1-5-21-111-222-333-1002"
	if _, err := svcDo(b, id2, &Request{Op: "credential", Profile: "bedrock"}, ui); err == nil {
		t.Fatal("second user reached the first user's key")
	}
}

type constSealer []byte

func (c constSealer) Name() string                          { return "const" }
func (c constSealer) Wrap([]byte) ([]byte, error)           { return nil, nil }
func (c constSealer) Unwrap([]byte, string) ([]byte, error) { return append([]byte(nil), c...), nil }

func TestMigrationIntoService(t *testing.T) {
	setupHome(t)
	aws := newFakeAWS(t)
	aws.keys["AKIAMIGRATE000000001"] = fakeUser{"111122223333", richardArn}
	writeAWS(t, "", "")
	local, _ := userBackend(t)
	k := &KeyPayload{AccessKeyID: "AKIAMIGRATE000000001", SecretAccessKey: "x"}
	local.e.SealKey("legacy", k, keyMeta(k, nil))
	if _, err := cred(local, "legacy", "", awsCaller); err != nil { // creates a signed pin
		t.Fatal(err)
	}
	b, id := newTestBroker(t)
	ui := &testUI{}
	pub, _ := localHelloPublicKey(false)
	svcDo(b, id, &Request{Op: "enroll", Args: map[string]string{"pub": encodePublicKey(pub)}}, ui)

	ok, env, err := local.e.OpenKey("legacy", "migrate")
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := local.e.LoadPin("legacy")
	if _, err := svcDo(b, id, &Request{Op: "migrate", Profile: "legacy", Bundle: &MigrationBundle{Key: ok, Meta: env.Meta, Pin: pin}}, ui); err != nil {
		t.Fatal(err)
	}
	n := len(devPrompts)
	if _, err := svcDo(b, id, &Request{Op: "credential", Profile: "legacy"}, ui); err != nil || len(devPrompts) != n+1 {
		t.Fatalf("migrated key: %v", err)
	}
	if _, err := svcDo(b, id, &Request{Op: "migrate", Profile: "legacy", Bundle: &MigrationBundle{Key: &KeyPayload{AccessKeyID: "AKIAXX", SecretAccessKey: "y"}}}, ui); err == nil {
		t.Fatal("second migration over an existing key accepted")
	}
}

func TestQuarantineOverMFAProfile(t *testing.T) {
	setupHome(t)
	newFakeAWS(t)
	b, _ := userBackend(t)
	k := &KeyPayload{AccessKeyID: "AKIAMFAUSER000000001", SecretAccessKey: "x", MFAMode: "pc", MFASerial: "s", MFASeed: "JBSWY3DPEHPK3PXP"}
	b.e.SealKey("prod", k, keyMeta(k, nil))
	writeAWS(t, "[prod]\naws_access_key_id = AKIANEWKEY0000000001\naws_secret_access_key = NEWSECRET\n", "")
	sd, _ := statusOf(b)
	res, err := importKeys(b, nil, sd.Settings, "watcher")
	if err != nil || len(res.Quarantined) != 1 {
		t.Fatalf("quarantine: %+v %v", res, err)
	}
	if c, _ := os.ReadFile(credentialsFile()); strings.Contains(string(c), "NEWSECRET") {
		t.Fatal("quarantined key left in plain text")
	}
	got, _, _ := b.e.OpenKey("prod", "")
	if got.AccessKeyID != "AKIAMFAUSER000000001" || got.MFASeed == "" {
		t.Fatal("MFA profile was overwritten")
	}
}

func TestRedactAndCredentialLine(t *testing.T) {
	if got := redact("arn:aws:iam::111122223333:mfa/x AKIAABCDEFGHIJKL1234 aws_secret_access_key = abc"); strings.Contains(got, "11112222") || strings.Contains(got, "ABCDEFGHIJKL") || strings.Contains(got, "abc") {
		t.Fatal(got)
	}
	cliExeOverride = `C:\Program Files\aws-cli-zsp\zsp.exe`
	defer func() { cliExeOverride = "" }()
	if l := credentialProcessLine("bedrock", tierWrite); l != `"C:\Program Files\aws-cli-zsp\zsp.exe" credential-process --profile bedrock --tier write` {
		t.Fatal(l)
	}
	if !credentialProcessOK(credentialProcessLine("x", ""), cliExeOverride) {
		t.Fatal("own line not accepted by the guard")
	}
}
