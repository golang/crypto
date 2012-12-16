// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"testing"
)

func TestSafeString(t *testing.T) {
	strings := map[string]string{
		"\x20\x0d\x0a":  "\x20\x0d\x0a",
		"flibble":       "flibble",
		"new\x20line":   "new\x20line",
		"123456\x07789": "123456 789",
		"\t\t\x10\r\n":  "\t\t \r\n",
	}

	for s, expected := range strings {
		actual := safeString(s)
		if expected != actual {
			t.Errorf("expected: %v, actual: %v", []byte(expected), []byte(actual))
		}
	}
}

func TestAlgoNameSupported(t *testing.T) {
	supported := map[string]interface{}{
		KeyAlgoRSA:          new(rsa.PublicKey),
		KeyAlgoDSA:          new(dsa.PublicKey),
		KeyAlgoECDSA256:     &ecdsa.PublicKey{Curve: elliptic.P256()},
		KeyAlgoECDSA384:     &ecdsa.PublicKey{Curve: elliptic.P384()},
		KeyAlgoECDSA521:     &ecdsa.PublicKey{Curve: elliptic.P521()},
		CertAlgoRSAv01:      &OpenSSHCertV01{Key: new(rsa.PublicKey)},
		CertAlgoDSAv01:      &OpenSSHCertV01{Key: new(dsa.PublicKey)},
		CertAlgoECDSA256v01: &OpenSSHCertV01{Key: &ecdsa.PublicKey{Curve: elliptic.P256()}},
		CertAlgoECDSA384v01: &OpenSSHCertV01{Key: &ecdsa.PublicKey{Curve: elliptic.P384()}},
		CertAlgoECDSA521v01: &OpenSSHCertV01{Key: &ecdsa.PublicKey{Curve: elliptic.P521()}},
	}

	for expected, key := range supported {
		actual := algoName(key)
		if expected != actual {
			t.Errorf("expected: %s, actual: %s", expected, actual)
		}
	}

}

func TestAlgoNameNotSupported(t *testing.T) {
	notSupported := []interface{}{
		&ecdsa.PublicKey{Curve: elliptic.P224()},
		&OpenSSHCertV01{Key: &ecdsa.PublicKey{Curve: elliptic.P224()}},
	}

	panicTest := func(key interface{}) (algo string, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = errors.New(r.(string))
			}
		}()
		algo = algoName(key)
		return
	}

	for _, unsupportedKey := range notSupported {
		if algo, err := panicTest(unsupportedKey); err == nil {
			t.Errorf("Expected a panic, Got: %s (for type %T)", algo, unsupportedKey)
		}
	}
}
