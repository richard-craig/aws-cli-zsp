package main

import (
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// testEndpoint redirects all AWS calls to a local fake (unit tests only).
var testEndpoint string

// lastClockSkew records how far the local clock is from AWS (from the Date header).
var lastClockSkew atomic.Int64

type AWSError struct {
	Code, Message string
	Status        int
}

func (e *AWSError) Error() string { return fmt.Sprintf("%s: %s", e.Code, e.Message) }

func isAWSCode(err error, code string) bool {
	var ae *AWSError
	return errors.As(err, &ae) && ae.Code == code
}

// queryCall makes a signed AWS Query-protocol POST (STS and IAM both speak it)
// and decodes the XML response into out.
func queryCall(c Creds, host, region, service, action, version string, params url.Values, out any) error {
	form := url.Values{}
	for k, v := range params {
		form[k] = v
	}
	form.Set("Action", action)
	form.Set("Version", version)
	body := []byte(form.Encode())

	now := time.Now().UTC()
	headers := map[string]string{
		"host":         host,
		"content-type": "application/x-www-form-urlencoded; charset=utf-8",
		"x-amz-date":   now.Format("20060102T150405Z"),
	}
	if c.SessionToken != "" {
		headers["x-amz-security-token"] = c.SessionToken
	}
	auth := signRequest(c, "POST", "/", nil, headers, body, region, service, now)

	target := "https://" + host + "/"
	if testEndpoint != "" {
		target = testEndpoint + "/" + service
	}
	req, err := http.NewRequest("POST", target, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range headers {
		if k != "host" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("User-Agent", "aws-cli-zsp-windows/"+version_)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if d, perr := http.ParseTime(resp.Header.Get("Date")); perr == nil {
		lastClockSkew.Store(int64(time.Since(d)))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 300 {
		var er struct {
			Error struct {
				Code    string `xml:"Code"`
				Message string `xml:"Message"`
			} `xml:"Error"`
		}
		if xml.Unmarshal(raw, &er) == nil && er.Error.Code != "" {
			return &AWSError{Code: er.Error.Code, Message: er.Error.Message, Status: resp.StatusCode}
		}
		return &AWSError{Code: resp.Status, Message: strings.TrimSpace(string(raw)), Status: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	return xml.Unmarshal(raw, out)
}

// STS ---------------------------------------------------------------------------------

// stsHost uses the regional endpoint when a region is known. Tokens from a
// regional STS endpoint work in opt-in regions (af-south-1, me-south-1, ...);
// tokens from the global endpoint do not, by default.
func stsHost(region string) (string, string) {
	if region == "" {
		return "sts.amazonaws.com", "us-east-1"
	}
	if strings.HasPrefix(region, "cn-") {
		return "sts." + region + ".amazonaws.com.cn", region
	}
	return "sts." + region + ".amazonaws.com", region
}

type stsCredentials struct {
	AccessKeyID     string    `xml:"AccessKeyId"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	SessionToken    string    `xml:"SessionToken"`
	Expiration      time.Time `xml:"Expiration"`
}

func getSessionToken(c Creds, region string, d time.Duration, mfaSerial, code string) (*Session, error) {
	host, sreg := stsHost(region)
	p := url.Values{"DurationSeconds": {strconv.Itoa(int(d.Seconds()))}}
	if mfaSerial != "" {
		p.Set("SerialNumber", mfaSerial)
		p.Set("TokenCode", code)
	}
	var out struct {
		Result struct {
			Credentials stsCredentials `xml:"Credentials"`
		} `xml:"GetSessionTokenResult"`
	}
	if err := queryCall(c, host, sreg, "sts", "GetSessionToken", "2011-06-15", p, &out); err != nil {
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

type CallerIdentity struct {
	Account string `xml:"Account"`
	Arn     string `xml:"Arn"`
	UserID  string `xml:"UserId"`
}

func getCallerIdentity(c Creds, region string) (*CallerIdentity, error) {
	host, sreg := stsHost(region)
	var out struct {
		Result CallerIdentity `xml:"GetCallerIdentityResult"`
	}
	if err := queryCall(c, host, sreg, "sts", "GetCallerIdentity", "2011-06-15", nil, &out); err != nil {
		return nil, err
	}
	return &out.Result, nil
}

// IAM ---------------------------------------------------------------------------------

func iamCall(c Creds, action string, p url.Values, out any) error {
	return queryCall(c, "iam.amazonaws.com", "us-east-1", "iam", action, "2010-05-08", p, out)
}

type AccessKeyMeta struct {
	AccessKeyID string    `xml:"AccessKeyId"`
	Status      string    `xml:"Status"`
	CreateDate  time.Time `xml:"CreateDate"`
}

func iamListAccessKeys(c Creds, user string) ([]AccessKeyMeta, error) {
	var out struct {
		Result struct {
			Members []AccessKeyMeta `xml:"AccessKeyMetadata>member"`
		} `xml:"ListAccessKeysResult"`
	}
	err := iamCall(c, "ListAccessKeys", url.Values{"UserName": {user}}, &out)
	return out.Result.Members, err
}

type KeyLastUsed struct {
	LastUsedDate time.Time `xml:"LastUsedDate"`
	ServiceName  string    `xml:"ServiceName"`
	Region       string    `xml:"Region"`
}

func iamKeyLastUsed(c Creds, akid string) (*KeyLastUsed, error) {
	var out struct {
		Result struct {
			UserName string      `xml:"UserName"`
			Last     KeyLastUsed `xml:"AccessKeyLastUsed"`
		} `xml:"GetAccessKeyLastUsedResult"`
	}
	err := iamCall(c, "GetAccessKeyLastUsed", url.Values{"AccessKeyId": {akid}}, &out)
	return &out.Result.Last, err
}

func iamCreateAccessKey(c Creds, user string) (akid, secret string, err error) {
	var out struct {
		Result struct {
			Key struct {
				AccessKeyID     string `xml:"AccessKeyId"`
				SecretAccessKey string `xml:"SecretAccessKey"`
			} `xml:"AccessKey"`
		} `xml:"CreateAccessKeyResult"`
	}
	err = iamCall(c, "CreateAccessKey", url.Values{"UserName": {user}}, &out)
	return out.Result.Key.AccessKeyID, out.Result.Key.SecretAccessKey, err
}

func iamDeleteAccessKey(c Creds, user, akid string) error {
	return iamCall(c, "DeleteAccessKey", url.Values{"UserName": {user}, "AccessKeyId": {akid}}, nil)
}

func iamPutUserPolicy(c Creds, user, name, doc string) error {
	return iamCall(c, "PutUserPolicy", url.Values{"UserName": {user}, "PolicyName": {name}, "PolicyDocument": {doc}}, nil)
}

func iamDeleteUserPolicy(c Creds, user, name string) error {
	return iamCall(c, "DeleteUserPolicy", url.Values{"UserName": {user}, "PolicyName": {name}}, nil)
}

func iamHasUserPolicy(c Creds, user, name string) (bool, error) {
	err := iamCall(c, "GetUserPolicy", url.Values{"UserName": {user}, "PolicyName": {name}}, nil)
	if isAWSCode(err, "NoSuchEntity") {
		return false, nil
	}
	return err == nil, err
}

// iamCreateVirtualMFA returns the device serial (ARN) and the raw base32 seed.
func iamCreateVirtualMFA(c Creds, name string) (serial, seedB32 string, err error) {
	var out struct {
		Result struct {
			Dev struct {
				Serial string `xml:"SerialNumber"`
				Seed   string `xml:"Base32StringSeed"`
			} `xml:"VirtualMFADevice"`
		} `xml:"CreateVirtualMFADeviceResult"`
	}
	if err = iamCall(c, "CreateVirtualMFADevice", url.Values{"VirtualMFADeviceName": {name}}, &out); err != nil {
		return "", "", err
	}
	// The Query API returns the seed as base64(base32-ascii).
	raw, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(out.Result.Dev.Seed))
	if derr != nil {
		return "", "", fmt.Errorf("decode MFA seed: %w", derr)
	}
	return out.Result.Dev.Serial, string(raw), nil
}

func iamEnableMFA(c Creds, user, serial, code1, code2 string) error {
	return iamCall(c, "EnableMFADevice", url.Values{
		"UserName": {user}, "SerialNumber": {serial},
		"AuthenticationCode1": {code1}, "AuthenticationCode2": {code2},
	}, nil)
}

func iamDeactivateMFA(c Creds, user, serial string) error {
	return iamCall(c, "DeactivateMFADevice", url.Values{"UserName": {user}, "SerialNumber": {serial}}, nil)
}

func iamDeleteVirtualMFA(c Creds, serial string) error {
	return iamCall(c, "DeleteVirtualMFADevice", url.Values{"SerialNumber": {serial}}, nil)
}

func userNameFromArn(arn string) string {
	if i := strings.Index(arn, ":user/"); i >= 0 {
		p := arn[i+6:]
		if j := strings.LastIndex(p, "/"); j >= 0 { // user paths: user/path/name
			p = p[j+1:]
		}
		return p
	}
	return ""
}

func accountFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 4 {
		return parts[4]
	}
	return ""
}
