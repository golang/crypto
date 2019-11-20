// Copyright 2019 ProtonTech AG.
//

package ecdh

import (
	"testing"
	"crypto/rand"
)

// Some OpenPGP implementations, such as gpg 2.2.12, do not accept ECDH private
// keys if they're not masked. This is because they're not of the proper form,
// cryptographically, and they don't mask input keys during crypto operations.
// This test checks if the keys that this library stores or outputs are
// properly masked.
func TestGenerateMaskedPrivateKeyX25519(t *testing.T) {
	priv, _, err := x25519GenerateKeyPairBytes(rand.Reader)
	if err != nil  {
		t.Fatal(err)
	}

	// Check masking
	// 3 lsb are 0
	if priv[0]<<5 != 0 {
		t.Fatalf("Priv. key is not masked (3 lsb should be unset): %X", priv)
	}
	// MSB is 0
	if priv[31]>>7 != 0 {
		t.Fatalf("Priv. key is not masked (MSB should be unset): %X", priv)
	}
	// Second-MSB is 1
	if priv[31]>>6 != 1 {
		t.Fatalf("Priv. key is not masked (second MSB should be set): %X", priv)
	}
}
