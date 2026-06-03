// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

type macData struct {
	Mac        digestInfo
	MacSalt    []byte
	Iterations int `asn1:"optional,default:1"`
}

// from PKCS#7:
type digestInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	Digest    []byte
}

var (
	oidSHA1 = asn1.ObjectIdentifier([]int{1, 3, 14, 3, 2, 26})
)

func verifyMac(macData *macData, message, password []byte) error {
	if !macData.Mac.Algorithm.Algorithm.Equal(oidSHA1) {
		return NotImplementedError("unknown digest algorithm: " + macData.Mac.Algorithm.Algorithm.String())
	}
	if macData.Iterations <= 0 || macData.Iterations > 10_000_000 {
		return errors.New("pkcs12: iteration count out of safe range")
	}
	key := pbkdf(sha1Sum, 20, 64, macData.MacSalt, password, macData.Iterations, 3, 20)

	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(macData.Mac.Digest, expectedMAC) {
		return ErrIncorrectPassword
	}
	return nil
}
