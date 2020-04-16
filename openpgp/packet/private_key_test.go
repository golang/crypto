// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"hash"
	mathrand "math/rand"
	"testing"
	"time"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/rsa"
)

const maxMessageLength = 1 << 10

var privateKeyTests = []struct {
	privateKeyHex string
	creationTime  time.Time
}{
	{
		privKeyRSAHex,
		time.Unix(0x4cc349a8, 0),
	},
	{
		privKeyElGamalHex,
		time.Unix(0x4df9ee1a, 0),
	},
}

func TestExternalPrivateKeyRead(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		err = privKey.Decrypt([]byte("wrong password"))
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect key", i)
			continue
		}

		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

// En/decryption of private keys provided externally, with random passwords
func TestExternalPrivateKeyEncryptDecryptRandomizeSlow(t *testing.T) {
	for i, test := range privateKeyTests {
		packet, err := Read(readerFromHex(test.privateKeyHex))
		if err != nil {
			t.Errorf("#%d: failed to parse: %s", i, err)
			continue
		}

		privKey := packet.(*PrivateKey)

		if !privKey.Encrypted {
			t.Errorf("#%d: private key isn't encrypted", i)
			continue
		}

		// Decrypt with the correct password
		err = privKey.Decrypt([]byte("testing"))
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		// Encrypt with another (possibly empty) password
		randomPassword := make([]byte, mathrand.Intn(30))
		rand.Read(randomPassword)
		err = privKey.Encrypt(randomPassword)
		if err != nil {
			t.Errorf("#%d: failed to encrypt: %s", i, err)
			continue
		}

		// Try to decrypt with incorrect password
		incorrect := make([]byte, 1+mathrand.Intn(30))
		for rand.Read(incorrect); bytes.Equal(incorrect, randomPassword); {
			rand.Read(incorrect)
		}
		err = privKey.Decrypt(incorrect)
		if err == nil {
			t.Errorf("#%d: decrypted with incorrect password\nPassword is:%vDecrypted with:%v", i, randomPassword, incorrect)
			continue
		}

		// Try to decrypt with old password
		err = privKey.Decrypt([]byte("testing"))
		if err == nil {
			t.Errorf("#%d: decrypted with old password", i)
			continue
		}

		// Decrypt with correct password
		err = privKey.Decrypt(randomPassword)
		if err != nil {
			t.Errorf("#%d: failed to decrypt: %s", i, err)
			continue
		}

		if !privKey.CreationTime.Equal(test.creationTime) || privKey.Encrypted {
			t.Errorf("#%d: bad result, got: %#v", i, privKey)
		}
	}
}

func populateHash(hashFunc crypto.Hash, msg []byte) (hash.Hash, error) {
	h := hashFunc.New()
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return h, nil
}

func TestExternalRSAPrivateKey(t *testing.T) {
	privKeyDER, _ := hex.DecodeString(pkcs1PrivKeyHex)
	rsaPriv, err := x509.ParsePKCS1PrivateKey(privKeyDER)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	xrsaPriv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: rsaPriv.PublicKey.E,
			N: rsaPriv.PublicKey.N,
		},
		D:      rsaPriv.D,
		Primes: rsaPriv.Primes,
	}
	xrsaPriv.Precompute()
	if err := NewRSAPrivateKey(time.Now(), xrsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}
	for j := 0; j < 256; j++ {
		msg := make([]byte, maxMessageLength)
		rand.Read(msg)

		h, err := populateHash(sig.Hash, msg)
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Sign(h, priv, nil); err != nil {
			t.Fatal(err)
		}

		if h, err = populateHash(sig.Hash, msg); err != nil {
			t.Fatal(err)
		}
		if err := priv.VerifySignature(h, sig); err != nil {
			t.Fatal(err)
		}
	}
}

func TestECDSAPrivateKeysRandomizeFast(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewECDSAPrivateKey(time.Now(), ecdsaPriv).Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, mathrand.Intn(maxMessageLength))
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

type rsaSigner struct {
	*rsa.PrivateKey
}

func TestRSASignerPrivateKeysRandomizeSlow(t *testing.T) {
	// Generate random key
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), &rsaSigner{rsaPriv})

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}

	// Sign random message
	msg := make([]byte, maxMessageLength)
	h, err := populateHash(sig.Hash, msg)

	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}

	// Verify signature
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}

	// Try to verify signature with wrong key
	incorrectRsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	incorrectPriv := NewSignerPrivateKey(time.Now(), &rsaSigner{incorrectRsaPriv})
	if err = incorrectPriv.VerifySignature(h, sig); err == nil {
		t.Fatalf(
			"Verified signature with incorrect key.\nCorrect key:  \n%v\nIncorrect key:\n%v\nSignature:%v",
			priv, incorrectPriv, sig)
	}
}

type ecdsaSigner struct {
	*ecdsa.PrivateKey
}

func TestECDSASignerPrivateKeysRandomizeFast(t *testing.T) {
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), &ecdsaSigner{ecdsaPriv})

	if priv.PubKeyAlgo != PubKeyAlgoECDSA {
		t.Fatal("NewSignerPrivateKey should have made an ECSDA private key")
	}

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoECDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, mathrand.Intn(maxMessageLength))
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}

	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

func TestEdDSASignerPrivateKeyRandomizeFast(t *testing.T) {
	_, eddsaPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), eddsaPriv)

	if priv.PubKeyAlgo != PubKeyAlgoEdDSA {
		t.Fatal("NewSignerPrivateKey should have made a EdDSA private key")
	}

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoEdDSA,
		Hash:       crypto.SHA256,
	}
	msg := make([]byte, maxMessageLength)
	rand.Read(msg)

	h, err := populateHash(sig.Hash, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := sig.Sign(h, priv, nil); err != nil {
		t.Fatal(err)
	}
	if h, err = populateHash(sig.Hash, msg); err != nil {
		t.Fatal(err)
	}
	if err := priv.VerifySignature(h, sig); err != nil {
		t.Fatal(err)
	}
}

// Tests correctness when encrypting an EdDSA private key with a password.
func TestEncryptDecryptEdDSAPrivateKeyRandomizeFast(t *testing.T) {
	password := make([]byte, 20)
	_, err := rand.Read(password)
	if err != nil {
		panic(err)
	}
	_, primaryKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	privKey := *NewEdDSAPrivateKey(time.Now(), primaryKey)
	copiedPrivKey := make([]byte, len(primaryKey))
	copy(copiedPrivKey, privKey.PrivateKey.(ed25519.PrivateKey))
	// Encrypt private key with random passphrase
	privKey.Encrypt(password)
	// Decrypt and check correctness
	privKey.Decrypt(password)
	if !bytes.Equal(privKey.PrivateKey.(ed25519.PrivateKey), copiedPrivKey) {
		t.Fatalf("Private key was not correctly decrypted:\ngot:\n%v\nwant:\n%v", privKey.PrivateKey, copiedPrivKey)
	}
}

func TestIssue11505(t *testing.T) {
	// parsing a rsa private key with p or q == 1 used to panic due to a divide by zero
	_, _ = Read(readerFromHex("9c3004303030300100000011303030000000000000010130303030303030303030303030303030303030303030303030303030303030303030303030303030303030"))
}
