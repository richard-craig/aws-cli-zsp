package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// RFC 6238 TOTP (SHA-1, 30 s, 6 digits), which is what AWS virtual MFA uses.

func decodeBase32Seed(seed string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(seed), " ", ""))
	s = strings.TrimRight(s, "=")
	return base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
}

func hotp(key []byte, counter uint64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	m := hmac.New(sha1.New, key)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, code%mod)
}

func totpAt(seedB32 string, t time.Time) (string, error) {
	key, err := decodeBase32Seed(seedB32)
	if err != nil {
		return "", fmt.Errorf("bad MFA seed: %w", err)
	}
	defer zero(key)
	return hotp(key, uint64(t.Unix())/30, 6), nil
}

// totpFresh returns a code for the current window, waiting for the next window
// when fewer than 3 s remain so AWS does not receive an expiring code.
func totpFresh(seedB32 string) (string, error) {
	if left := 30 - time.Now().Unix()%30; left < 3 {
		time.Sleep(time.Duration(left)*time.Second + 200*time.Millisecond)
	}
	return totpAt(seedB32, time.Now())
}

func validSixDigits(code string) bool {
	if len(code) != 6 {
		return false
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
