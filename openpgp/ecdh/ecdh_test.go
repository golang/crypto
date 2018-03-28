// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ecdh

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha512"
	"testing"

	"golang.org/x/crypto/openpgp/internal/algorithm"
)

var (
	testCurveOID    = []byte{0x05, 0x2B, 0x81, 0x04, 0x00, 0x22} // MPI encoded oidCurveP384
	testFingerprint = make([]byte, 20)
)


func TestEncryptDecrypt(t *testing.T) {
	kdf := KDF{
		Hash:   algorithm.SHA512,
		Cipher: algorithm.AES256,
	}

	priv, err := GenerateKey(elliptic.P384(), kdf, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("hello world")
	vsG, m, err := Encrypt(rand.Reader, &priv.PublicKey, message, testCurveOID, testFingerprint)
	if err != nil {
		t.Errorf("error encrypting: %s", err)
	}
	message2, err := Decrypt(priv, vsG, m, testCurveOID, testFingerprint)
	if err != nil {
		t.Errorf("error decrypting: %s", err)
	}
	if !bytes.Equal(message2, message) {
		t.Errorf("decryption failed, got: %x, want: %x", message2, message)
	}
}
