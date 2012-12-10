package test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"

	"code.google.com/p/go.crypto/ssh"
)

var (
	validKey = `AAAAB3NzaC1yc2EAAAADAQABAAABAQDEX/dPu4PmtvgK3La9zioCEDrJ` +
		`yUr6xEIK7Pr+rLgydcqWTU/kt7w7gKjOw4vvzgHfjKl09CWyvgb+y5dCiTk` +
		`9MxI+erGNhs3pwaoS+EavAbawB7iEqYyTep3YaJK+4RJ4OX7ZlXMAIMrTL+` +
		`UVrK89t56hCkFYaAgo3VY+z6rb/b3bDBYtE1Y2tS7C3au73aDgeb9psIrSV` +
		`86ucKBTl5X62FnYiyGd++xCnLB6uLximM5OKXfLzJQNS/QyZyk12g3D8y69` +
		`Xw1GzCSKX1u1+MQboyf0HJcG2ryUCLHdcDVppApyHx2OLq53hlkQ/yxdflD` +
		`qCqAE4j+doagSsIfC1T2T`

	authWithOptions = []string{
		`# comments to ignore before any keys...`,
		``,
		`env="HOME=/home/root",no-port-forwarding ssh-rsa ` + validKey + ` user@host`,
		`# comments to ignore, along with a blank line`,
		``,
		`env="HOME=/home/root2" ssh-rsa ` + validKey + ` user2@host2`,
		``,
		`# more comments, plus a invalid entry`,
		`ssh-rsa data-that-will-not-parse user@host3`,
	}

	authOptions              = strings.Join(authWithOptions, "\n")
	authWithCRLF             = strings.Join(authWithOptions, "\r\n")
	authInvalid              = []byte(`ssh-rsa`)
	authWithQuotedCommaInEnv = []byte(`env="HOME=/home/root,dir",no-port-forwarding ssh-rsa ` + validKey + `   user@host`)
	authWithQuotedSpaceInEnv = []byte(`env="HOME=/home/root dir",no-port-forwarding ssh-rsa ` + validKey + ` user@host`)
	authWithQuotedQuoteInEnv = []byte(`env="HOME=/home/\"root dir",no-port-forwarding` + "\t" + `ssh-rsa` + "\t" + validKey + `   user@host`)

	authWithDoubleQuotedQuote = []byte(`no-port-forwarding,env="HOME=/home/ \"root dir\"" ssh-rsa ` + validKey + "\t" + `user@host`)
	authWithInvalidSpace      = []byte(`env="HOME=/home/root dir", no-port-forwarding ssh-rsa ` + validKey + ` user@host
#more to follow but still no valid keys`)
	authWithMissingQuote = []byte(`env="HOME=/home/root,no-port-forwarding ssh-rsa ` + validKey + ` user@host
env="HOME=/home/root",shared-control ssh-rsa ` + validKey + ` user@host`)
)

func TestMarshalParsePublicKey(t *testing.T) {
	pub := getTestPublicKey(t)
	authKeys := ssh.MarshalAuthorizedKey(pub)
	actualFields := strings.Fields(string(authKeys))
	if len(actualFields) == 0 {
		t.Fatalf("failed authKeys: %v", authKeys)
	}

	// drop the comment
	expectedFields := strings.Fields(keys["authorized_keys"])[0:2]

	if !reflect.DeepEqual(actualFields, expectedFields) {
		t.Errorf("got %v, expected %v", actualFields, expectedFields)
	}

	actPub, _, _, _, ok := ssh.ParseAuthorizedKey([]byte(keys["authorized_keys"]))
	if !ok {
		t.Fatalf("cannot parse %v", keys["authorized_keys"])
	}
	if !reflect.DeepEqual(actPub, pub) {
		t.Errorf("got %v, expected %v", actPub, pub)
	}
}

type authResult struct {
	pubKey   interface{} //*rsa.PublicKey
	options  []string
	comments string
	rest     string
	ok       bool
}

func testAuthorizedKeys(t *testing.T, authKeys []byte, expected []authResult) {
	rest := authKeys
	var values []authResult
	for len(rest) > 0 {
		var r authResult
		r.pubKey, r.comments, r.options, rest, r.ok = ssh.ParseAuthorizedKey(rest)
		r.rest = string(rest)
		values = append(values, r)
	}

	if !reflect.DeepEqual(values, expected) {
		t.Errorf("got %q, expected %q", values, expected)
	}

}

func getTestPublicKey(t *testing.T) *rsa.PublicKey {
	block, _ := pem.Decode([]byte(testClientPrivateKey))
	if block == nil {
		t.Fatalf("pem.Decode: %v", testClientPrivateKey)
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS1PrivateKey: %v", err)
	}

	return &priv.PublicKey
}

func TestAuth(t *testing.T) {
	pub := getTestPublicKey(t)
	rest2 := strings.Join(authWithOptions[3:], "\n")
	rest3 := strings.Join(authWithOptions[6:], "\n")
	testAuthorizedKeys(t, []byte(authOptions), []authResult{
		{pub, []string{`env="HOME=/home/root"`, "no-port-forwarding"}, "user@host", rest2, true},
		{pub, []string{`env="HOME=/home/root2"`}, "user2@host2", rest3, true},
		{nil, nil, "", "", false},
	})
}

func TestAuthWithCRLF(t *testing.T) {
	pub := getTestPublicKey(t)
	rest2 := strings.Join(authWithOptions[3:], "\r\n")
	rest3 := strings.Join(authWithOptions[6:], "\r\n")
	testAuthorizedKeys(t, []byte(authWithCRLF), []authResult{
		{pub, []string{`env="HOME=/home/root"`, "no-port-forwarding"}, "user@host", rest2, true},
		{pub, []string{`env="HOME=/home/root2"`}, "user2@host2", rest3, true},
		{nil, nil, "", "", false},
	})
}

func TestAuthWithQuotedSpaceInEnv(t *testing.T) {
	pub := getTestPublicKey(t)
	testAuthorizedKeys(t, []byte(authWithQuotedSpaceInEnv), []authResult{
		{pub, []string{`env="HOME=/home/root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedCommaInEnv(t *testing.T) {
	pub := getTestPublicKey(t)
	testAuthorizedKeys(t, []byte(authWithQuotedCommaInEnv), []authResult{
		{pub, []string{`env="HOME=/home/root,dir"`, "no-port-forwarding"}, "user@host", "", true},
	})
}

func TestAuthWithQuotedQuoteInEnv(t *testing.T) {
	pub := getTestPublicKey(t)
	testAuthorizedKeys(t, []byte(authWithQuotedQuoteInEnv), []authResult{
		{pub, []string{`env="HOME=/home/\"root dir"`, "no-port-forwarding"}, "user@host", "", true},
	})

	testAuthorizedKeys(t, []byte(authWithDoubleQuotedQuote), []authResult{
		{pub, []string{"no-port-forwarding", `env="HOME=/home/ \"root dir\""`}, "user@host", "", true},
	})

}

func TestAuthWithInvalidSpace(t *testing.T) {
	testAuthorizedKeys(t, []byte(authWithInvalidSpace), []authResult{
		{nil, nil, "", "", false},
	})
}

func TestAuthWithMissingQuote(t *testing.T) {
	pub := getTestPublicKey(t)
	testAuthorizedKeys(t, []byte(authWithMissingQuote), []authResult{
		{pub, []string{`env="HOME=/home/root"`, `shared-control`}, "user@host", "", true},
	})
}

func TestInvalidEntry(t *testing.T) {
	_, _, _, _, ok := ssh.ParseAuthorizedKey(authInvalid)
	if ok {
		t.Errorf("Expected invalid entry, returned valid entry")
	}
}
