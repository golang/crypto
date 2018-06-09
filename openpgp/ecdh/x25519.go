// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ecdh implements ECDH encryption, suitable for OpenPGP,
// as specified in RFC 6637, section 8.
package ecdh

import (
	"errors"
	"io"
	"math/big"

	"golang.org/x/crypto/openpgp/aes/keywrap"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/openpgp/internal/ecc"
)

func X25519GenerateParams(rand io.Reader) (priv [32]byte, x [32]byte, err error) {
	var n, helper = new (big.Int), new (big.Int)
	n.SetUint64(1)
	n.Lsh(n, 252)
	helper.SetString("27742317777372353535851937790883648493", 10)
	n.Add(n, helper)

	for true {
		_, err = io.ReadFull(rand, priv[:])
		if err != nil {
			return
		}
		// This is because, in tests, rand will return all zeros and we don't
		// want to get the point at infinity and loop forever.
		priv[1] ^= 0x42

		// If the scalar is out of range, sample another random number.
		if new(big.Int).SetBytes(priv[:]).Cmp(n) >= 0 {
			continue
		}

		curve25519.ScalarBaseMult(&x, &priv)
		return
	}
	return
}

func X25519GenerateKey(rand io.Reader, kdf KDF) (priv *PrivateKey, err error) {
	ci := ecc.FindByName("Curve25519")
	priv = new(PrivateKey)
	priv.PublicKey.Curve = ci.Curve
	d, ephemeralKey, err := X25519GenerateParams(rand)
	if err != nil {
		return nil, err
	}
	priv.PublicKey.KDF = kdf
	priv.D = make([]byte, 32)
	copyReversed(priv.D, d[:])
	priv.PublicKey.CurveType = ci.CurveType
	priv.PublicKey.Curve = ci.Curve
	priv.PublicKey.X = new (big.Int).SetBytes(ephemeralKey[:])
	priv.PublicKey.Y = new (big.Int)
	return priv, nil
}

func X25519Encrypt(random io.Reader, pub *PublicKey, msg, curveOID, fingerprint []byte) (vsG, c []byte, err error) {
	d, ephemeralKey, err := X25519GenerateParams(random)
	if err != nil {
		return nil, nil, err
	}
	var pubKey [32]byte

	if pub.X.BitLen() > 33 * 264 {
		return nil, nil, errors.New("ecdh: invalid key")
	}

	copy(pubKey[:], pub.X.Bytes()[1:])

	var zb [32]byte
	curve25519.ScalarBaseMult(&zb, &d)
	curve25519.ScalarMult(&zb, &d, &pubKey)
	var bigZb = new (big.Int)
	bigZb.SetBytes(zb[:])
	z, err := buildKey(pub, bigZb, curveOID, fingerprint)

	if err != nil {
		return nil, nil, err
	}

	if c, err = keywrap.Wrap(z, msg); err != nil {
		return nil, nil, err
	}

	var vsg [33]byte
	vsg[0] = 0x40
	copy(vsg[1:], ephemeralKey[:])

	return vsg[:], c, nil
}

func X25519Decrypt(priv *PrivateKey, vsG, m, curveOID, fingerprint []byte) (msg []byte, err error) {
	var zb, d, ephemeralKey[32]byte
	if len(vsG) != 33 || vsG[0] != 0x40 {
		return nil,  errors.New("ecdh: invalid key")
	}
	copy(ephemeralKey[:], vsG[1:33])

	copyReversed(d[:], priv.D)
	curve25519.ScalarBaseMult(&zb, &d)
	curve25519.ScalarMult(&zb, &d, &ephemeralKey)

	var bigZb = new(big.Int)
	bigZb.SetBytes(zb[:])

	z, err := buildKey(&priv.PublicKey, bigZb, curveOID, fingerprint)
	if err != nil {
		return nil, err
	}

	c, err := keywrap.Unwrap(z, m)
	if err != nil {
		return nil, err
	}

	return c[:len(c)-int(c[len(c)-1])], nil
}

func copyReversed(out []byte, in []byte) {
	for i := 31; i >= 0; i-- {
		out[31-i] = in[i]
	}
}