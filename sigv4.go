package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"time"
)

// AWS Signature Version 4, standard library only. Kept dependency-free on
// purpose: this binary handles your long-lived keys, so its supply chain is
// the Go standard library and nothing else.

type Creds struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func signingKey(secret, date, region, service string) []byte {
	k := hmacSHA256([]byte("AWS4"+secret), date)
	k = hmacSHA256(k, region)
	k = hmacSHA256(k, service)
	return hmacSHA256(k, "aws4_request")
}

// awsURIEncode is RFC 3986 encoding as SigV4 requires (space -> %20, keep ~).
func awsURIEncode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

func canonicalQuery(q url.Values) string {
	var pairs []string
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, awsURIEncode(k)+"="+awsURIEncode(v))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// signRequest returns the Authorization header value. headers must already
// contain every header to sign (host, x-amz-date, ...); keys are lower-cased here.
func signRequest(c Creds, method, path string, query url.Values, headers map[string]string, body []byte,
	region, service string, now time.Time) string {

	amzDate := now.UTC().Format("20060102T150405Z")
	date := amzDate[:8]

	lower := map[string]string{}
	var names []string
	for k, v := range headers {
		lk := strings.ToLower(k)
		lower[lk] = strings.Join(strings.Fields(v), " ")
		names = append(names, lk)
	}
	sort.Strings(names)
	var ch strings.Builder
	for _, n := range names {
		ch.WriteString(n + ":" + lower[n] + "\n")
	}
	signed := strings.Join(names, ";")
	if path == "" {
		path = "/"
	}
	canonical := strings.Join([]string{
		method, path, canonicalQuery(query), ch.String(), signed, sha256Hex(body),
	}, "\n")

	scope := date + "/" + region + "/" + service + "/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canonical))
	sig := hex.EncodeToString(hmacSHA256(signingKey(c.SecretAccessKey, date, region, service), toSign))
	return "AWS4-HMAC-SHA256 Credential=" + c.AccessKeyID + "/" + scope + ", SignedHeaders=" + signed + ", Signature=" + sig
}
