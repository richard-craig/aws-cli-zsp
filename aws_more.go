package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// STS AssumeRole (v0.3 tiers). Called with the long-lived user key, so it is not
// role chaining and the role's own MaxSessionDuration applies.
func assumeRole(c Creds, region, roleArn, sessionName string, d time.Duration, mfaSerial, code string) (*Session, error) {
	host, sreg := stsHost(region)
	p := url.Values{
		"RoleArn":         {roleArn},
		"RoleSessionName": {sessionName},
		"DurationSeconds": {strconv.Itoa(int(d.Seconds()))},
	}
	if mfaSerial != "" {
		p.Set("SerialNumber", mfaSerial)
		p.Set("TokenCode", code)
	}
	var out struct {
		Result struct {
			Credentials stsCredentials `xml:"Credentials"`
		} `xml:"AssumeRoleResult"`
	}
	if err := queryCall(c, host, sreg, "sts", "AssumeRole", "2011-06-15", p, &out); err != nil {
		return nil, err
	}
	cr := out.Result.Credentials
	if cr.AccessKeyID == "" || cr.SessionToken == "" {
		return nil, errors.New("STS returned no credentials")
	}
	return &Session{
		AccessKeyID: cr.AccessKeyID, SecretAccessKey: cr.SecretAccessKey, SessionToken: cr.SessionToken,
		Expiration: cr.Expiration, MFA: mfaSerial != "", Issued: time.Now().UTC(),
	}, nil
}

var sessionNameBad = regexp.MustCompile(`[^\w+=,.@-]`)

// roleSessionName is zsp-<iam user>-<profile>-<r|w>. The prefix lets the scoped
// revoke and source-IP policies (and the auto-revoke Lambda) target only zsp
// sessions of this user, never other users of the same role.
func roleSessionName(user, profile, tier string) string {
	t := "r"
	if tier == tierWrite {
		t = "w"
	}
	suffix := "-" + sessionNameBad.ReplaceAllString(profile, "-") + "-" + t
	head := "zsp-" + sessionNameBad.ReplaceAllString(user, "-")
	if len(head)+len(suffix) > 64 {
		if len(head) > 40 {
			head = head[:40]
		}
		if len(head)+len(suffix) > 64 {
			suffix = suffix[:64-len(head)]
		}
	}
	return head + suffix
}

func roleNameFromArn(arn string) string {
	if i := strings.Index(arn, ":role/"); i >= 0 {
		r := arn[i+6:]
		if j := strings.LastIndex(r, "/"); j >= 0 {
			r = r[j+1:]
		}
		return r
	}
	return ""
}

func iamPutRolePolicy(c Creds, role, name, doc string) error {
	return iamCall(c, "PutRolePolicy", url.Values{"RoleName": {role}, "PolicyName": {name}, "PolicyDocument": {doc}}, nil)
}

func iamDeleteRolePolicy(c Creds, role, name string) error {
	return iamCall(c, "DeleteRolePolicy", url.Values{"RoleName": {role}, "PolicyName": {name}}, nil)
}

// shipHTTP has a short timeout: shipping runs right after a refusal, and must
// never hold up the error the user is waiting for.
var shipHTTP = &http.Client{Timeout: 8 * time.Second}

// S3 PutObject, used only to ship the audit trail. Object Lock buckets require
// Content-MD5 (or a checksum), so it is always sent.
func s3PutObject(c Creds, bucket, region, key string, body []byte, contentType string) error {
	host := bucket + ".s3." + region + ".amazonaws.com"
	if region == "us-east-1" {
		host = bucket + ".s3.amazonaws.com"
	}
	path := "/" + s3EncodePath(key)
	now := time.Now().UTC()
	sum := md5.Sum(body)
	headers := map[string]string{
		"host":                 host,
		"x-amz-date":           now.Format("20060102T150405Z"),
		"x-amz-content-sha256": sha256Hex(body),
		"content-md5":          base64.StdEncoding.EncodeToString(sum[:]),
		"content-type":         contentType,
	}
	if c.SessionToken != "" {
		headers["x-amz-security-token"] = c.SessionToken
	}
	auth := signRequest(c, "PUT", path, nil, headers, body, region, "s3", now)
	target := "https://" + host + path
	if testEndpoint != "" {
		target = testEndpoint + "/s3" + path
	}
	req, err := http.NewRequest("PUT", target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", auth)
	resp, err := shipHTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode >= 300 {
		code := regexp.MustCompile(`<Code>([^<]+)</Code>`).FindStringSubmatch(string(raw))
		if len(code) > 1 {
			return &AWSError{Code: code[1], Message: resp.Status, Status: resp.StatusCode}
		}
		return &AWSError{Code: resp.Status, Message: truncate(string(raw), 200), Status: resp.StatusCode}
	}
	return nil
}

func s3EncodePath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = awsURIEncode(p)
	}
	return strings.Join(parts, "/")
}

// publicIP asks checkip.amazonaws.com, so a source-IP binding can be checked
// before it is applied (and cannot lock you out).
func publicIP() (string, error) {
	target := "https://checkip.amazonaws.com/"
	if testEndpoint != "" {
		target = testEndpoint + "/checkip"
	}
	resp, err := httpClient.Get(target)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	ip := strings.TrimSpace(string(b))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("unexpected answer from checkip: %q", truncate(ip, 40))
	}
	return ip, nil
}

func ipInCIDRs(ip string, cidrs []string) bool {
	p := net.ParseIP(ip)
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(p) {
			return true
		}
		if q := net.ParseIP(c); q != nil && q.Equal(p) {
			return true
		}
	}
	return false
}
