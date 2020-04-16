// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
)

var pubKeyTests = []struct {
	hexData        string
	hexFingerprint string
	creationTime   time.Time
	pubKeyAlgo     PublicKeyAlgorithm
	keyId          uint64
	keyIdString    string
	keyIdShort     string
}{
	{rsaPkDataHex, rsaFingerprintHex, time.Unix(0x4d3c5c10, 0), PubKeyAlgoRSA, 0xa34d7e18c20c31bb, "A34D7E18C20C31BB", "C20C31BB"},
	{dsaPkDataHex, dsaFingerprintHex, time.Unix(0x4d432f89, 0), PubKeyAlgoDSA, 0x8e8fbe54062f19ed, "8E8FBE54062F19ED", "062F19ED"},
	{ecdsaPkDataHex, ecdsaFingerprintHex, time.Unix(0x5071c294, 0), PubKeyAlgoECDSA, 0x43fe956c542ca00b, "43FE956C542CA00B", "542CA00B"},
	{ecdhPkDataHex, ecdhFingerprintHex, time.Unix(0x4d530592, 0), PubKeyAlgoECDH, 0xaa8B938f9a201946, "AA8B938F9A201946", "9A201946"},
	{eddsaPkDataHex, eddsaFingerprintHex, time.Unix(0x056e2132b, 0), PubKeyAlgoEdDSA, 0x907e75e1dd99ad8, "0907E75E1DD99AD8", "1DD99AD8"},
}

func TestPublicKeyRead(t *testing.T) {
	for i, test := range pubKeyTests {
		packet, err := Read(readerFromHex(test.hexData))
		if err != nil {
			t.Errorf("#%d: Read error: %s", i, err)
			continue
		}
		pk, ok := packet.(*PublicKey)
		if !ok {
			t.Errorf("#%d: failed to parse, got: %#v", i, packet)
			continue
		}
		if pk.PubKeyAlgo != test.pubKeyAlgo {
			t.Errorf("#%d: bad public key algorithm got:%x want:%x", i, pk.PubKeyAlgo, test.pubKeyAlgo)
		}
		if !pk.CreationTime.Equal(test.creationTime) {
			t.Errorf("#%d: bad creation time got:%v want:%v", i, pk.CreationTime, test.creationTime)
		}
		expectedFingerprint, _ := hex.DecodeString(test.hexFingerprint)
		if !bytes.Equal(expectedFingerprint, pk.Fingerprint[:]) {
			t.Errorf("#%d: bad fingerprint got:%x want:%x", i, pk.Fingerprint[:], expectedFingerprint)
		}
		if pk.KeyId != test.keyId {
			t.Errorf("#%d: bad keyid got:%x want:%x", i, pk.KeyId, test.keyId)
		}
		if g, e := pk.KeyIdString(), test.keyIdString; g != e {
			t.Errorf("#%d: bad KeyIdString got:%q want:%q", i, g, e)
		}
		if g, e := pk.KeyIdShortString(), test.keyIdShort; g != e {
			t.Errorf("#%d: bad KeyIdShortString got:%q want:%q", i, g, e)
		}
	}
}

func TestPublicKeySerialize(t *testing.T) {
	for i, test := range pubKeyTests {
		packet, err := Read(readerFromHex(test.hexData))
		if err != nil {
			t.Errorf("#%d: Read error: %s", i, err)
			continue
		}
		pk, ok := packet.(*PublicKey)
		if !ok {
			t.Errorf("#%d: failed to parse, got: %#v", i, packet)
			continue
		}
		serializeBuf := bytes.NewBuffer(nil)
		err = pk.Serialize(serializeBuf)
		if err != nil {
			t.Errorf("#%d: failed to serialize: %s", i, err)
			continue
		}

		packet, err = Read(serializeBuf)
		if err != nil {
			t.Errorf("#%d: Read error (from serialized data): %s", i, err)
			continue
		}
		pk, ok = packet.(*PublicKey)
		if !ok {
			t.Errorf("#%d: failed to parse serialized data, got: %#v", i, packet)
			continue
		}
	}
}

func TestEcc384Serialize(t *testing.T) {
	r := readerFromHex(ecc384PubHex)
	var w bytes.Buffer
	for i := 0; i < 2; i++ {
		// Public key
		p, err := Read(r)
		if err != nil {
			t.Error(err)
		}
		pubkey := p.(*PublicKey)
		if !bytes.Equal(pubkey.oid.Bytes(), []byte{0x2b, 0x81, 0x04, 0x00, 0x22}) {
			t.Errorf("Unexpected pubkey OID: %x", pubkey.oid.Bytes())
		}
		if !bytes.Equal(pubkey.p.Bytes()[:5], []byte{0x04, 0xf6, 0xb8, 0xc5, 0xac}) {
			t.Errorf("Unexpected pubkey P[:5]: %x", pubkey.p.Bytes())
		}
		if pubkey.KeyId != 0x098033880F54719F {
			t.Errorf("Unexpected pubkey ID: %x", pubkey.KeyId)
		}
		err = pubkey.Serialize(&w)
		if err != nil {
			t.Error(err)
		}
		// User ID
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		uid := p.(*UserId)
		if uid.Id != "ec_dsa_dh_384 <openpgp@brainhub.org>" {
			t.Error("Unexpected UID:", uid.Id)
		}
		err = uid.Serialize(&w)
		if err != nil {
			t.Error(err)
		}
		// User ID Sig
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		uidSig := p.(*Signature)
		err = pubkey.VerifyUserIdSignature(uid.Id, pubkey, uidSig)
		if err != nil {
			t.Error(err, ": UID")
		}
		err = uidSig.Serialize(&w)
		if err != nil {
			t.Error(err)
		}
		// Subkey
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		subkey := p.(*PublicKey)
		if !bytes.Equal(subkey.oid.Bytes(), []byte{0x2b, 0x81, 0x04, 0x00, 0x22}) {
			t.Errorf("Unexpected subkey OID: %x", subkey.oid.Bytes())
		}
		if !bytes.Equal(subkey.p.Bytes()[:5], []byte{0x04, 0x2f, 0xaa, 0x84, 0x02}) {
			t.Errorf("Unexpected subkey P[:5]: %x", subkey.p.Bytes())
		}
		if !bytes.Equal(subkey.kdf.Bytes(), []byte{0x01, 0x09, 0x09}) {
			t.Errorf("Unexpected subkey KDF: %x", subkey.kdf.Bytes())
		}
		if subkey.KeyId != 0xAA8B938F9A201946 {
			t.Errorf("Unexpected subkey ID: %x", subkey.KeyId)
		}
		err = subkey.Serialize(&w)
		if err != nil {
			t.Error(err)
		}
		// Subkey Sig
		p, err = Read(r)
		if err != nil {
			t.Error(err)
		}
		subkeySig := p.(*Signature)
		err = pubkey.VerifyKeySignature(subkey, subkeySig)
		if err != nil {
			t.Error(err)
		}
		err = subkeySig.Serialize(&w)
		if err != nil {
			t.Error(err)
		}
		// Now read back what we've written again
		r = bytes.NewBuffer(w.Bytes())
		w.Reset()
	}
}

func TestP256KeyID(t *testing.T) {
	// Confirm that key IDs are correctly calculated for ECC keys.
	ecdsaPub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     fromHex("81fbbc20eea9e8d1c3ceabb0a8185925b113d1ac42cd5c78403bd83da19235c6"),
		Y:     fromHex("5ed6db13d91db34507d0129bf88981878d29adbf8fcd1720afdb767bb3fcaaff"),
	}
	pub := NewECDSAPublicKey(time.Unix(1297309478, 0), ecdsaPub)

	const want = uint64(0xd01055fbcadd268e)
	if pub.KeyId != want {
		t.Errorf("want key ID: %x, got %x", want, pub.KeyId)
	}
}

func fromHex(hex string) *big.Int {
	n, ok := new(big.Int).SetString(hex, 16)
	if !ok {
		panic("bad hex number: " + hex)
	}
	return n
}
