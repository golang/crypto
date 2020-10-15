// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package wycheproof

import (
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestChaCha20Poly1305(t *testing.T) {
	// AeadTestVector
	type AeadTestVector struct {

		// additional authenticated data
		Aad string `json:"aad,omitempty"`

		// A brief description of the test case
		Comment string `json:"comment,omitempty"`

		// the ciphertext (without iv and tag)
		Ct string `json:"ct,omitempty"`

		// A list of flags
		Flags []string `json:"flags,omitempty"`

		// the nonce
		Iv string `json:"iv,omitempty"`

		// the key
		Key string `json:"key,omitempty"`

		// the plaintext
		Msg string `json:"msg,omitempty"`

		// Test result
		Result string `json:"result,omitempty"`

		// the authentication tag
		Tag string `json:"tag,omitempty"`

		// Identifier of the test case
		TcId int `json:"tcId,omitempty"`
	}

	// Notes a description of the labels used in the test vectors
	type Notes struct {
	}

	// AeadTestGroup
	type AeadTestGroup struct {

		// the IV size in bits
		IvSize int `json:"ivSize,omitempty"`

		// the keySize in bits
		KeySize int `json:"keySize,omitempty"`

		// the expected size of the tag in bits
		TagSize int               `json:"tagSize,omitempty"`
		Tests   []*AeadTestVector `json:"tests,omitempty"`
		Type    interface{}       `json:"type,omitempty"`
	}

	// Root
	type Root struct {

		// the primitive tested in the test file
		Algorithm string `json:"algorithm,omitempty"`

		// the version of the test vectors.
		GeneratorVersion string `json:"generatorVersion,omitempty"`

		// additional documentation
		Header []string `json:"header,omitempty"`

		// a description of the labels used in the test vectors
		Notes *Notes `json:"notes,omitempty"`

		// the number of test vectors in this test
		NumberOfTests int              `json:"numberOfTests,omitempty"`
		Schema        interface{}      `json:"schema,omitempty"`
		TestGroups    []*AeadTestGroup `json:"testGroups,omitempty"`
	}

	testAeadSealOpen := func(t *testing.T, aead cipher.AEAD, tv *AeadTestVector, recoverBadNonce func()) {
		defer recoverBadNonce()

		// Encrypt the message, then decrypt the new ciphertext and validate
		// the decrypted message.
		ciphertext := aead.Seal(nil, decodeHex(tv.Iv), decodeHex(tv.Msg), decodeHex(tv.Aad))
		msg, err := aead.Open(nil, decodeHex(tv.Iv), ciphertext, decodeHex(tv.Aad))
		if err != nil {
			t.Fatalf("#%d: decryption failed: %v", tv.TcId, err)
		}
		if got, want := hex.EncodeToString(msg), tv.Msg; got != want {
			t.Errorf("#%d: bad message after encrypting and decrypting: %s, want %v", tv.TcId, got, want)
		}

		// Decrypt the provided ciphertext and validate the decrypted message.
		tv.Ct += tv.Tag // append the tag to the ciphertext
		msg2, err := aead.Open(nil, decodeHex(tv.Iv), decodeHex(tv.Ct), decodeHex(tv.Aad))
		wantPass := shouldPass(tv.Result, tv.Flags, nil)
		if wantPass {
			if err != nil {
				t.Errorf("#%d, type: %s, comment: %q, decryption wanted success, got err: %v", tv.TcId, tv.Result, tv.Comment, err)
			}
			if got, want := hex.EncodeToString(ciphertext), tv.Ct; got != want {
				t.Errorf("#%d: ciphertext doesn't match: %s, want=%s", tv.TcId, got, want)
			}
			if got, want := hex.EncodeToString(msg2), tv.Msg; got != want {
				t.Errorf("#%d: bad message after decrypting ciphertext: %s, want %v", tv.TcId, got, want)
			}
		} else {
			if err == nil {
				t.Errorf("#%d, type: %s, comment: %q, decryption wanted error", tv.TcId, tv.Result, tv.Comment)
			}
		}
	}

	var root Root
	readTestVector(t, "chacha20_poly1305_test.json", &root)
	for _, tg := range root.TestGroups {
		for _, tv := range tg.Tests {
			aead, err := chacha20poly1305.New(decodeHex(tv.Key))
			if err != nil {
				t.Fatalf("#%d: %v", tv.TcId, err)
			}
			if tg.TagSize/8 != aead.Overhead() {
				t.Fatalf("#%d: bad tag length", tv.TcId)
			}
			testAeadSealOpen(t, aead, tv, func() {
				// A bad nonce causes a panic in AEAD.Seal and AEAD.Open,
				// so should be recovered. Fail the test if it broke for
				// some other reason.
				if r := recover(); r != nil {
					if tg.IvSize/8 == chacha20poly1305.NonceSize {
						t.Errorf("#%d: unexpected panic", tv.TcId)
					}
				}
			})
		}
	}
}
