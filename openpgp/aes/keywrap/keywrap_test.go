// Copyright 2014 Matthew Endsley
// All rights reserved
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted providing that the following conditions
// are met:
// 1. Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
// OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package keywrap

import (
	"bytes"
	"testing"
)

// A.1.8 - JSON Web Encryption
func TestWrap(t *testing.T) {
	key := []byte{64, 154, 239, 170, 64, 40, 195, 99, 19, 84, 192, 142, 192, 238, 207, 217}
	sharedKey := []byte{25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82}
	expectedWrappedKey := []byte{164, 255, 251, 1, 64, 200, 65, 200, 34, 197, 81, 143, 43, 211, 240, 38, 191, 161, 181, 117, 119, 68, 44, 80}

	wrappedKey, err := Wrap(sharedKey, key)
	if err != nil {
		t.Fatal("keywrap: failed to Wrap key: ", err)
	}

	if !bytes.Equal(expectedWrappedKey, wrappedKey) {
		t.Fatalf("unwrap: unexpected wrapped key:\n\t%v\n\t%v", expectedWrappedKey, wrappedKey)
	}
}

// A.1.8 - JSON Web Encryption
func TestUnwrap(t *testing.T) {
	sharedKey := []byte{25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82}
	wrappedKey := []byte{164, 255, 251, 1, 64, 200, 65, 200, 34, 197, 81, 143, 43, 211, 240, 38, 191, 161, 181, 117, 119, 68, 44, 80}
	expectedKey := []byte{64, 154, 239, 170, 64, 40, 195, 99, 19, 84, 192, 142, 192, 238, 207, 217}

	key, err := Unwrap(sharedKey, wrappedKey)
	if err != nil {
		t.Fatal("keywrap: failed to unwrap key: ", err)
	}

	if !bytes.Equal(expectedKey, key) {
		t.Fatalf("keywrap: unexpected wrapped key:\n\t%v\n\t%v", expectedKey, key)
	}
}

// Test wrap error cases.
func TestWrapError(t *testing.T) {
	plaintext := make([]byte, 7)
	key := make([]byte, 32)
	_, err := Wrap(key, plaintext)
	if err != ErrWrapPlaintext {
		t.Fatalf("keywrap: expected Wrap to fail with %v, but have err=%v", ErrWrapPlaintext, err)
	}

	plaintext = append(plaintext, byte(0))
	_, err = Wrap(key[:31], plaintext)
	if err != ErrInvalidKey {
		t.Fatalf("keywrap: expected Wrap to fail with %v, but have err=%v", ErrInvalidKey, err)
	}
}

// Test unwrap error cases.
func TestUnwrapError(t *testing.T) {
	key := []byte{64, 154, 239, 170, 64, 40, 195, 99, 19, 84, 192, 142, 192, 238, 207, 217}
	sharedKey := []byte{25, 172, 32, 130, 225, 114, 26, 181, 138, 106, 254, 192, 95, 133, 74, 82}
	wrapped, err := Wrap(key, sharedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	l := len(wrapped)
	_, err = Unwrap(key, wrapped[:l-2])
	if err != ErrUnwrapCiphertext {
		t.Fatalf("keywrap: expected Unwrap to fail with %v, but have err=%v", ErrUnwrapCiphertext, err)
	}

	l = len(key)
	_, err = Unwrap(key[:l-2], wrapped)
	if err != ErrInvalidKey {
		t.Fatalf("keywrap: expected Unwrap to fail with %v, but have err=%v", ErrInvalidKey, err)
	}

	wrapped[0]--
	_, err = Unwrap(key, wrapped)
	if err != ErrUnwrapFailed {
		t.Fatalf("keywrap: expected Unwrap to fail with %v, but have err=%v", ErrUnwrapFailed, err)
	}

}
