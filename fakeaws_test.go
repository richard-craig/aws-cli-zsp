//go:build !windows

package main

import (
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeAWS is a minimal STS + IAM + S3 that checks what zsp sends.
type fakeUser struct{ account, arn string }

type fakeAWS struct {
	mu         sync.Mutex
	keys       map[string]fakeUser // long-lived akid -> user
	sessions   map[string]string   // session akid -> arn it acts as
	mfaSeed    map[string]string   // serial -> seed
	usedCodes  map[string]bool
	roles      map[string]bool              // role ARNs that exist and trust everyone in the test
	userPols   map[string]map[string]string // user -> name -> doc
	rolePols   map[string]map[string]string // role name -> name -> doc
	objects    map[string][]byte            // s3 key -> body
	calls      map[string]int
	lastAssume map[string]string // last AssumeRole form
	publicIP   string
	n          int
}

var credRe = regexp.MustCompile(`Credential=([A-Z0-9]+)/`)

func newFakeAWS(t *testing.T) *fakeAWS {
	f := &fakeAWS{keys: map[string]fakeUser{}, sessions: map[string]string{}, mfaSeed: map[string]string{},
		usedCodes: map[string]bool{}, roles: map[string]bool{}, userPols: map[string]map[string]string{},
		rolePols: map[string]map[string]string{}, objects: map[string][]byte{}, calls: map[string]int{}, publicIP: "196.25.1.10"}
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	testEndpoint = srv.URL
	t.Cleanup(func() { testEndpoint = "" })
	return f
}

func xmlErr(w http.ResponseWriter, code, msg string) {
	w.WriteHeader(403)
	fmt.Fprintf(w, `<ErrorResponse><Error><Code>%s</Code><Message>%s</Message></Error></ErrorResponse>`, code, msg)
}

func (f *fakeAWS) creds(w http.ResponseWriter, result string, d time.Duration, arn string) {
	f.n++
	sid := fmt.Sprintf("ASIATEST%012d", f.n)
	f.sessions[sid] = arn
	fmt.Fprintf(w, `<R><%s><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>ss</SecretAccessKey><SessionToken>tok%d</SessionToken><Expiration>%s</Expiration></Credentials></%s></R>`,
		result, sid, f.n, time.Now().Add(d).UTC().Format(time.RFC3339), result)
}

func (f *fakeAWS) checkMFA(w http.ResponseWriter, serial, code string) bool {
	if serial == "" {
		return true
	}
	want, _ := totpAt(f.mfaSeed[serial], time.Now())
	if f.usedCodes[serial+code] {
		xmlErr(w, "AccessDenied", "MultiFactorAuthentication failed with invalid MFA one time pass code.")
		return false
	}
	if code != want {
		xmlErr(w, "AccessDenied", "MultiFactorAuthentication failed")
		return false
	}
	f.usedCodes[serial+code] = true
	return true
}

func (f *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.URL.Path == "/checkip":
		fmt.Fprintln(w, f.publicIP)
		return
	case strings.HasPrefix(r.URL.Path, "/s3/"):
		body, _ := io.ReadAll(r.Body)
		sum := md5.Sum(body)
		if r.Header.Get("Content-Md5") != base64.StdEncoding.EncodeToString(sum[:]) || r.Header.Get("X-Amz-Content-Sha256") != sha256Hex(body) {
			w.WriteHeader(400)
			fmt.Fprint(w, "<Error><Code>BadDigest</Code></Error>")
			return
		}
		f.objects[strings.TrimPrefix(r.URL.Path, "/s3/")] = body
		f.calls["PutObject"]++
		return
	}
	_ = r.ParseForm()
	form := map[string]string{}
	for k := range r.Form {
		form[k] = r.Form.Get(k)
	}
	action := form["Action"]
	f.calls[action]++
	m := credRe.FindStringSubmatch(r.Header.Get("Authorization"))
	if m == nil {
		xmlErr(w, "MissingAuthenticationToken", "no auth")
		return
	}
	akid := m[1]
	u, isKey := f.keys[akid]
	actingArn := u.arn
	if !isKey {
		a, ok := f.sessions[akid]
		if !ok {
			xmlErr(w, "InvalidClientTokenId", "unknown key")
			return
		}
		actingArn = a
	}
	userName := userNameFromArn(actingArn)
	switch action {
	case "GetSessionToken":
		if !isKey {
			xmlErr(w, "AccessDenied", "session credentials cannot call GetSessionToken")
			return
		}
		if !f.checkMFA(w, form["SerialNumber"], form["TokenCode"]) {
			return
		}
		f.creds(w, "GetSessionTokenResult", time.Hour, u.arn)
	case "AssumeRole":
		if !f.roles[form["RoleArn"]] {
			xmlErr(w, "AccessDenied", "not authorized to assume "+form["RoleArn"])
			return
		}
		if !f.checkMFA(w, form["SerialNumber"], form["TokenCode"]) {
			return
		}
		f.lastAssume = form
		parts := strings.Split(form["RoleArn"], ":")
		f.creds(w, "AssumeRoleResult", time.Hour, "arn:aws:sts::"+parts[4]+":assumed-role/"+roleNameFromArn(form["RoleArn"])+"/"+form["RoleSessionName"])
	case "GetCallerIdentity":
		acct := strings.Split(actingArn, ":")[4]
		fmt.Fprintf(w, `<R><GetCallerIdentityResult><Account>%s</Account><Arn>%s</Arn><UserId>X</UserId></GetCallerIdentityResult></R>`, acct, actingArn)
	case "PutUserPolicy":
		if f.userPols[form["UserName"]] == nil {
			f.userPols[form["UserName"]] = map[string]string{}
		}
		f.userPols[form["UserName"]][form["PolicyName"]] = form["PolicyDocument"]
		fmt.Fprint(w, "<R/>")
	case "DeleteUserPolicy":
		if _, ok := f.userPols[form["UserName"]][form["PolicyName"]]; !ok {
			xmlErr(w, "NoSuchEntity", "no policy")
			return
		}
		delete(f.userPols[form["UserName"]], form["PolicyName"])
		fmt.Fprint(w, "<R/>")
	case "GetUserPolicy":
		if _, ok := f.userPols[form["UserName"]][form["PolicyName"]]; !ok {
			xmlErr(w, "NoSuchEntity", "no policy")
			return
		}
		fmt.Fprint(w, "<R/>")
	case "PutRolePolicy":
		if f.rolePols[form["RoleName"]] == nil {
			f.rolePols[form["RoleName"]] = map[string]string{}
		}
		f.rolePols[form["RoleName"]][form["PolicyName"]] = form["PolicyDocument"]
		fmt.Fprint(w, "<R/>")
	case "DeleteRolePolicy":
		delete(f.rolePols[form["RoleName"]], form["PolicyName"])
		fmt.Fprint(w, "<R/>")
	case "ListAccessKeys":
		fmt.Fprintf(w, `<R><ListAccessKeysResult><AccessKeyMetadata><member><AccessKeyId>%s</AccessKeyId><Status>Active</Status><CreateDate>2026-01-01T00:00:00Z</CreateDate></member></AccessKeyMetadata></ListAccessKeysResult></R>`, akid)
	case "GetAccessKeyLastUsed":
		fmt.Fprint(w, `<R><GetAccessKeyLastUsedResult><UserName>u</UserName><AccessKeyLastUsed><ServiceName>N/A</ServiceName><Region>N/A</Region></AccessKeyLastUsed></GetAccessKeyLastUsedResult></R>`)
	default:
		_ = userName
		xmlErr(w, "InvalidAction", action)
	}
}
