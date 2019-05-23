// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"io/ioutil"
	"strings"
	"testing"
	"time"
)

type algorithmSet struct {
	message                string
	name                   string
	privateKey             string
	publicKey              string
	password               string
	encryptedSignedMessage string
}

var testSets = []algorithmSet{
	{
		test_message,
		"rsa",
		rsa_priv_key,
		rsa_pub_key,
		rsa_pass,
		rsa_enc_sign_message,
	},
	{
		test_message,
		"dsa",
		dsa_elgamal_priv,
		dsa_elgamal_pub,
		dsa_elgamal_pass,
		dsa_elgamal_enc_sign_message,
	},
	{
		test_message,
		"p256",
		p256_priv,
		p256_pub,
		p256_pass,
		p256_enc_sign_message,
	},
	{
		test_message,
		"p384",
		p384_priv,
		p384_pub,
		p384_pass,
		p384_enc_sign_message,
	},
	{
		test_message,
		"p521",
		p521_priv,
		p521_pub,
		p521_pass,
		p521_enc_sign_message,
	},
	{
		test_message,
		"secp256k1",
		secp256k1_priv,
		secp256k1_pub,
		secp256k1_pass,
		secp256k1_enc_sign_message,
	},
	{
		test_message,
		"ed25519",
		ed25519_priv,
		ed25519_pub,
		ed25519_pass,
		ed25519_enc_sign_message,
	},
	{
		brainpool_testmessage,
		"brainpoolp256r1",
		brainpoolp256r1_priv,
		brainpoolp256r1_pub,
		brainpoolp256r1_pass,
		brainpoolp256r1_enc_sign_message,
	},
	{
		brainpool_testmessage,
		"brainpoolp384r1",
		brainpoolp384r1_priv,
		brainpoolp384r1_pub,
		brainpoolp384r1_pass,
		brainpoolp384r1_enc_sign_message,
	},
	{
		brainpool_testmessage,
		"brainpoolp512r1",
		brainpoolp512r1_priv,
		brainpoolp512r1_pub,
		brainpoolp512r1_pass,
		brainpoolp512r1_enc_sign_message,
	},
}

type keySet struct {
	name string
	cfg  *packet.Config
}

var keySets = []keySet{
	{
		"rsa",
		&packet.Config{RSABits: 2048, Algorithm: packet.PubKeyAlgoRSA},
	},
	{
		"rsa",
		&packet.Config{RSABits: 4096, Algorithm: packet.PubKeyAlgoRSA},
	},
	{
		"ed25519",
		&packet.Config{Algorithm: packet.PubKeyAlgoEdDSA},
	},
}

func readArmoredPublicKey(t *testing.T, publicKey string) EntityList {
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(publicKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
	return keys
}

func readArmoredPrivateKey(t *testing.T, privateKey string, password string) EntityList {
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(privateKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
	var keyObject = keys[0].PrivateKey
	if password != "" {
		if err := keyObject.Decrypt([]byte("invalid password")); err == nil {
			t.Fatal("It should not be possible to decrypt with an invalid password")
		}
	}
	return keys
}

func decryptionTest(t *testing.T, testSet algorithmSet, privateKey EntityList) {
	if testSet.encryptedSignedMessage == "" {
		return
	}
	var prompt = func(keys []Key, symmetric bool) ([]byte, error) {
		err := keys[0].PrivateKey.Decrypt([]byte(testSet.password))
		if err != nil {
			t.Errorf("prompt: error decrypting key: %s", err)
			return nil, err
		}
		return nil, nil
	}
	sig, err := armor.Decode(strings.NewReader(testSet.encryptedSignedMessage))
	if err != nil {
		t.Error(err)
		return
	}
	md, err := ReadMessage(sig.Body, privateKey, prompt, nil)
	if err != nil {
		t.Error(err)
		return
	}

	body, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Error(err)
		return
	}

	var stringBody = string(body)
	if stringBody != testSet.message {
		t.Fatal("Decrypted body did not match expected body")
	}

	// We'll see a sig error here after reading in the UnverifiedBody above,
	// if there was one to see.
	if err = md.SignatureError; err != nil {
		t.Error(err)
		return
	}

	if md.SignatureV3 != nil {
		t.Errorf("Did not expect a signature V3 back")
		return
	}
	if md.Signature == nil {
		t.Errorf("Expected a signature to be set")
		return
	}
	return
}

func encryptDecryptTest(t *testing.T, testSetFrom algorithmSet, testSetTo algorithmSet, privateKeyFrom EntityList, publicKeyFrom EntityList, publicKeyTo EntityList, privateKeyTo EntityList) {
	var signed *Entity
	var prompt = func(keys []Key, symmetric bool) ([]byte, error) {
		err := keys[0].PrivateKey.Decrypt([]byte(testSetTo.password))
		if err != nil {
			t.Errorf("Prompt: error decrypting key: %s", err)
			return nil, err
		}
		return nil, nil
	}
	signed = privateKeyFrom[0]
	signed.PrivateKey.Decrypt([]byte(testSetFrom.password))

	buf := new(bytes.Buffer)
	w, err := Encrypt(buf, publicKeyTo[:1], signed, nil /* no hints */, nil)
	if err != nil {
		t.Fatalf("Error in Encrypt: %s", err)
	}

	const message = "testing"
	_, err = w.Write([]byte(message))
	if err != nil {
		t.Fatalf("Error writing plaintext: %s", err)
	}
	err = w.Close()
	if err != nil {
		t.Fatalf("Error closing WriteCloser: %s", err)
	}

	md, err := ReadMessage(buf, append(privateKeyTo, publicKeyFrom[0]), prompt, nil)
	if err != nil {
		t.Fatalf("Error reading message: %s", err)
	}

	if !md.IsEncrypted {
		t.Fatal("The message should be encrypted")
	}
	signKey, _ := signed.SigningKey(time.Now())
	expectedKeyId := signKey.PublicKey.KeyId
	if md.SignedByKeyId != expectedKeyId {
		t.Fatalf("Message signed by wrong key id, got: %v, want: %v", *md.SignedBy, expectedKeyId)
	}
	if md.SignedBy == nil {
		t.Fatalf("Failed to find the signing Entity")
	}

	plaintext, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		t.Fatalf("Error reading encrypted contents: %s", err)
	}

	encryptKey, _ := publicKeyTo[0].EncryptionKey(time.Now())
	expectedEncKeyId := encryptKey.PublicKey.KeyId
	if len(md.EncryptedToKeyIds) != 1 || md.EncryptedToKeyIds[0] != expectedEncKeyId {
		t.Errorf("Expected message to be encrypted to %v, but got %#v", expectedKeyId, md.EncryptedToKeyIds)
	}

	if string(plaintext) != message {
		t.Errorf("got: %s, want: %s", string(plaintext), message)
	}

	if md.SignatureError != nil {
		t.Errorf("Signature error: %s", md.SignatureError)
	}
	if md.Signature == nil {
		t.Error("Signature missing")
	}
}

func signVerifyTest(t *testing.T, testSetFrom algorithmSet, privateKeyFrom EntityList, publicKeyFrom EntityList, binary bool) {
	var signed *Entity
	signed = privateKeyFrom[0]
	signed.PrivateKey.Decrypt([]byte(testSetFrom.password))

	buf := new(bytes.Buffer)
	message := bytes.NewReader(bytes.NewBufferString("testing 漢字 \r\n \n \r\n").Bytes())
	if binary {
		ArmoredDetachSign(buf, signed, message, nil)
	} else {
		ArmoredDetachSignText(buf, signed, message, nil)
	}

	signatureReader := bytes.NewReader(buf.Bytes())

	wrongmessage := bytes.NewReader(bytes.NewBufferString("testing 漢字").Bytes())
	wrongsigner, err := CheckArmoredDetachedSignature(publicKeyFrom, wrongmessage, signatureReader, nil)

	if err == nil || wrongsigner != nil {
		t.Fatal("Expected the signature to not verify")
		return
	}

	message.Seek(0, io.SeekStart)
	signatureReader.Seek(0, io.SeekStart)

	wronglineendings := bytes.NewReader(bytes.NewBufferString("testing 漢字 \n \r\n \n").Bytes())
	wronglinesigner, err := CheckArmoredDetachedSignature(publicKeyFrom, wronglineendings, signatureReader, nil)

	if binary {
		if err == nil || wronglinesigner != nil {
			t.Fatal("Expected the signature to not verify")
			return
		}
	} else {
		if err != nil {
			t.Errorf("signature error: %s", err)
			return
		}
		if wronglinesigner == nil {
			t.Errorf("signer is nil")
			return
		}
		if wronglinesigner.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
			t.Errorf("wrong signer got:%x want:%x", wronglinesigner.PrimaryKey.KeyId, 0)
		}
	}

	message.Seek(0, io.SeekStart)
	signatureReader.Seek(0, io.SeekStart)

	signer, err := CheckArmoredDetachedSignature(publicKeyFrom, message, signatureReader, nil)

	if err != nil {
		t.Errorf("signature error: %s", err)
		return
	}
	if signer == nil {
		t.Errorf("signer is nil")
		return
	}
	if signer.PrimaryKey.KeyId != signed.PrimaryKey.KeyId {
		t.Errorf("wrong signer got:%x want:%x", signer.PrimaryKey.KeyId, 0)
	}

	return
}

func algorithmTest(t *testing.T, testSet algorithmSet) {
	var privateKeyFrom = readArmoredPrivateKey(t, testSet.privateKey, testSet.password)
	var publicKeyFrom = readArmoredPublicKey(t, testSet.publicKey)
	t.Run(fmt.Sprintf("DecryptPreparedMessage"),
		func(t *testing.T) {
			decryptionTest(t, testSet, privateKeyFrom)
		})
	t.Run("encryptDecrypt", func(t *testing.T) {
		for _, testSetTo := range testSets {
			t.Run(testSetTo.name,
				func(t *testing.T) {
					var publicKeyTo = readArmoredPublicKey(t, testSetTo.publicKey)
					var privateKeyTo = readArmoredPrivateKey(t, testSetTo.privateKey, testSetTo.password)
					encryptDecryptTest(t, testSet, testSetTo, privateKeyFrom, publicKeyFrom, publicKeyTo, privateKeyTo)
				})
		}
	})
	t.Run("signVerify", func(t *testing.T) {
		t.Run("binary", func(t *testing.T) {
			signVerifyTest(t, testSet, privateKeyFrom, publicKeyFrom, true)
		})
		t.Run("text", func(t *testing.T) {
			signVerifyTest(t, testSet, privateKeyFrom, publicKeyFrom, false)
		})
	})
}

func makeKeyGenTestSets() (testSets []algorithmSet, err error) {
	email := "sunny@sunny.sunny"
	comments := ""
	password := "123"

	for _, keySet := range keySets {

		newTestSet := algorithmSet{}
		newTestSet.name = keySet.name + "_keygen"
		newTestSet.password = password
		newTestSet.message = test_message

		newEntity, _ := NewEntity(email, comments, email, keySet.cfg)
		if err = newEntity.SelfSign(nil); err != nil {
			return
		}

		rawPwd := []byte(password)
		if newEntity.PrivateKey != nil && !newEntity.PrivateKey.Encrypted {
			if err = newEntity.PrivateKey.Encrypt(rawPwd); err != nil {
				return
			}
		}

		for _, sub := range newEntity.Subkeys {
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err = sub.PrivateKey.Encrypt(rawPwd); err != nil {
					return
				}
			}
		}

		w := bytes.NewBuffer(nil)
		if err = newEntity.SerializePrivateNoSign(w, nil); err != nil {
			return
		}

		serialized := w.Bytes()

		privateKey, _ := ArmorWithType(serialized, "PGP PRIVATE KEY BLOCK")
		newTestSet.privateKey = privateKey
		newTestSet.publicKey, _ = PublicKey(privateKey)

		testSets = append(testSets, newTestSet)
	}
	return
}

// ArmorWithType make bytes input to armor format
func ArmorWithType(input []byte, armorType string) (string, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, armorType, nil)
	if err != nil {
		return "", err
	}
	_, err = w.Write(input)
	if err != nil {
		return "", err
	}
	w.Close()
	return b.String(), nil
}

func PublicKey(privateKey string) (string, error) {
	privKeyReader := strings.NewReader(privateKey)
	entries, err := ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return "", err
	}

	var outBuf bytes.Buffer
	for _, e := range entries {
		e.Serialize(&outBuf)
	}

	outString, err := ArmorWithType(outBuf.Bytes(), "PGP PUBLIC KEY BLOCK")
	if err != nil {
		return "", nil
	}

	return outString, nil
}

func TestEndToEnd(t *testing.T) {
	keyGenTestSets, err := makeKeyGenTestSets()
	if err != nil {
		fmt.Println(err.Error())
		panic("Cannot proceed without generated keys")
	}
	testSets = append(testSets, keyGenTestSets...)

	for _, testSet := range testSets {
		t.Run(testSet.name,
			func(t *testing.T) {
				algorithmTest(t, testSet)
			})
	}
}

const test_message = "test問量鮮控到案進平"

const rsa_pass = "hello world"

const rsa_priv_key = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQH+BFJhL04BBADclrUEDDsm0PSZbQ6pml9FpzTyXiyCyDN+rMOsy9J300Oc10kt
/nyBej9vZSRcaW5VpNNj0iA+c1/w2FPf84zNsTzvDmuMaNHFUzky4/vkYuZra//3
+Ri7CF8RawSYQ/4IRbC9zqdBlzniyfQOW7Dp/LYe8eibnDSrmkQem0G0jwARAQAB
/gMDAu7L//czBpE40p1ZqO8K3k7UejemjsQqc7kOqnlDYd1Z6/3NEA/UM30Siipr
KjdIFY5+hp0hcs6EiiNq0PDfm/W2j+7HfrZ5kpeQVxDek4irezYZrl7JS2xezaLv
k0Fv/6fxasnFtjOM6Qbstu67s5Gpl9y06ZxbP3VpT62+Xeibn/swWrfiJjuGEEhM
bgnsMpHtzAz/L8y6KSzViG/05hBaqrvk3/GeEA6nE+o0+0a6r0LYLTemmq6FbaA1
PHo+x7k7oFcBFUUeSzgx78GckuPwqr2mNfeF+IuSRnrlpZl3kcbHASPAOfEkyMXS
sWGE7grCAjbyQyM3OEXTSyqnehvGS/1RdB6kDDxGwgE/QFbwNyEh6K4eaaAThW2j
IEEI0WEnRkPi9fXyxhFsCLSI1XhqTaq7iDNqJTxE+AX2b9ZuZXAxI3Tc/7++vEyL
3p18N/MB2kt1Wb1azmXWL2EKlT1BZ5yDaJuBQ8BhphM3tCRUZXN0IE1jVGVzdGlu
Z3RvbiA8dGVzdEBleGFtcGxlLmNvbT6IuQQTAQIAIwUCUmEvTgIbLwcLCQgHAwIB
BhUIAgkKCwQWAgMBAh4BAheAAAoJEEpjYTpNbkCUMAwD+gIK08qpEZSVas9qW+Ok
32wzNkwxe6PQgZwcyBqMQYZUcKagC8+89pMQQ5sKUGvpIgat42Tf1KLGPcvG4cDA
JZ6w2PYz9YHQqPh9LA+PAnV8m25TcGmKcKgvFUqQ3U53X/Y9sBP8HooRqfwwHcv9
pMgQmojmNbI4VHydRqIBePawnQH+BFJhL04BBADpH8+0EVolpPiOrXTKoBKTiyrB
UyxzodyJ8zmVJ3HMTEU/vidpQwzISwoc/ndDFMXQauq6xqBCD9m2BPQI3UdQzXnb
LsAI52nWCIqOkzM5NAKWoKhyXK9Y4UH4v9LAYQgl/stIISvCgG4mJ8lzzEBWvRdf
Qm2Ghb64/3V5NDdemwARAQAB/gMDAu7L//czBpE40iPcpLzL7GwBbWFhSWgSLy53
Md99Kxw3cApWCok2E8R9/4VS0490xKZIa5y2I/K8thVhqk96Z8Kbt7MRMC1WLHgC
qJvkeQCI6PrFM0PUIPLHAQtDJYKtaLXxYuexcAdKzZj3FHdtLNWCooK6n3vJlL1c
WjZcHJ1PH7USlj1jup4XfxsbziuysRUSyXkjn92GZLm+64vCIiwhqAYoizF2NHHG
hRTN4gQzxrxgkeVchl+ag7DkQUDANIIVI+A63JeLJgWJiH1fbYlwESByHW+zBFNt
qStjfIOhjrfNIc3RvsggbDdWQLcbxmLZj4sB0ydPSgRKoaUdRHJY0S4vp9ouKOtl
2au/P1BP3bhD0fDXl91oeheYth+MSmsJFDg/vZJzCJhFaQ9dp+2EnjN5auNCNbaI
beFJRHFf9cha8p3hh+AK54NRCT++B2MXYf+TPwqX88jYMBv8kk8vYUgo8128r1zQ
EzjviQE9BBgBAgAJBQJSYS9OAhsuAKgJEEpjYTpNbkCUnSAEGQECAAYFAlJhL04A
CgkQ4IT3RGwgLJe6ogQA2aaJEIBIXtgrs+8WSJ4k3DN4rRXcXaUZf667pjdD9nF2
3BzjFH6Z78JIGaxRHJdM7b05aE8YuzM8f3NIlT0F0OLq/TI2muYU9f/U2DQBuf+w
KTB62+PELVgi9MsXC1Qv/u/o1LZtmmxTFFOD35xKsxZZI2OJj2pQpqObW27M8Nlc
BQQAw2YA3fFc38qPK+PY4rZyTRdbvjyyX+1zeqIo8wn7QCQwXs+OGaH2fGoT35AI
SXuqKcWqoEuO7OBSEFThCXBfUYMC01OrqKEswPm/V3zZkLu01q12UMwZach28QwK
/YZly4ioND2tdazj17u2rU2dwtiHPe1iMqGgVMoQirfLc+k=
=lw5e
-----END PGP PRIVATE KEY BLOCK-----`

const rsa_pub_key = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EUmEvTgEEANyWtQQMOybQ9JltDqmaX0WnNPJeLILIM36sw6zL0nfTQ5zXSS3+
fIF6P29lJFxpblWk02PSID5zX/DYU9/zjM2xPO8Oa4xo0cVTOTLj++Ri5mtr//f5
GLsIXxFrBJhD/ghFsL3Op0GXOeLJ9A5bsOn8th7x6JucNKuaRB6bQbSPABEBAAG0
JFRlc3QgTWNUZXN0aW5ndG9uIDx0ZXN0QGV4YW1wbGUuY29tPoi5BBMBAgAjBQJS
YS9OAhsvBwsJCAcDAgEGFQgCCQoLBBYCAwECHgECF4AACgkQSmNhOk1uQJQwDAP6
AgrTyqkRlJVqz2pb46TfbDM2TDF7o9CBnBzIGoxBhlRwpqALz7z2kxBDmwpQa+ki
Bq3jZN/UosY9y8bhwMAlnrDY9jP1gdCo+H0sD48CdXybblNwaYpwqC8VSpDdTndf
9j2wE/weihGp/DAdy/2kyBCaiOY1sjhUfJ1GogF49rC4jQRSYS9OAQQA6R/PtBFa
JaT4jq10yqASk4sqwVMsc6HcifM5lSdxzExFP74naUMMyEsKHP53QxTF0Grqusag
Qg/ZtgT0CN1HUM152y7ACOdp1giKjpMzOTQClqCoclyvWOFB+L/SwGEIJf7LSCEr
woBuJifJc8xAVr0XX0JthoW+uP91eTQ3XpsAEQEAAYkBPQQYAQIACQUCUmEvTgIb
LgCoCRBKY2E6TW5AlJ0gBBkBAgAGBQJSYS9OAAoJEOCE90RsICyXuqIEANmmiRCA
SF7YK7PvFkieJNwzeK0V3F2lGX+uu6Y3Q/Zxdtwc4xR+me/CSBmsURyXTO29OWhP
GLszPH9zSJU9BdDi6v0yNprmFPX/1Ng0Abn/sCkwetvjxC1YIvTLFwtUL/7v6NS2
bZpsUxRTg9+cSrMWWSNjiY9qUKajm1tuzPDZXAUEAMNmAN3xXN/Kjyvj2OK2ck0X
W748sl/tc3qiKPMJ+0AkMF7Pjhmh9nxqE9+QCEl7qinFqqBLjuzgUhBU4QlwX1GD
AtNTq6ihLMD5v1d82ZC7tNatdlDMGWnIdvEMCv2GZcuIqDQ9rXWs49e7tq1NncLY
hz3tYjKhoFTKEIq3y3Pp
=h/aX
-----END PGP PUBLIC KEY BLOCK-----`

const rsa_enc_sign_message = `-----BEGIN PGP MESSAGE-----

wYwD4IT3RGwgLJcBA/9txflPrGAhTRBISzQFVrMU2DYjuKy+XbOxMEsNy1H9
eXbCp6lP6AeKxAGrdDfJb209LoL6lvS4UpCV4eV+ucZ1tzZYBlqxTtMq4oC6
kIYidGJhROe33z3S6ocPN3Q6mYpuu2IT6V1+SBBmYiu3gwMOb8TRQzFcgCOg
yL3nx4ptEdLAQQEHUZCCsJFFw71i5oZf8/RPd0GM6L0RRG6DH+o/ab8LcT/l
TXqOfj3KvuHyE5lfwceZUJa0p6zpMLz/Clp/JJnGXtqBPcDlRlKYlot1+LMd
GYjUOM3S4ObnYOS9of4+6nLzWdl+kK7vHOIfTQPKfc9BuCgkBLwI2FjnJ10B
4gT495NMTj2IFC2okD5KaGu2rXfNWbS6bJOPWK+zsdwLHUO7PTB9sIDESp+6
oUTn8Fkc5QWKHSbafWIrEWKMLvJBD3HrIbLoGGd1O+RrFuMZV1qsaNh/pqDN
bBBgRdPauYvDNmUQb9UFfFGiD6GTqNEQd827fz+2r1Lp4OdEdkh1BMeQ
=wyjK
-----END PGP MESSAGE-----`

const dsa_elgamal_pass = "abcd"

const dsa_elgamal_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lQHhBFERnrMRBADmM0hIfkI3yosjgbWo9v0Lnr3CCE+8KsMszgVS+hBu0XfGraKm
ivcA2aaJimHqVYOP7gEnwFAxHBBpeTJcu5wzCFyJwEYqVeS3nnaIhBPplSF14Duf
i6bB9RV7KxVAg6aunmM2tAutqC+a0y2rDaf7jkJoZ9gWJe2zI+vraD6fiwCgxvHo
3IgULB9RqIqpLoMgXfcjC+cD/1jeJlKRm+n71ryYwT/ECKsspFz7S36z6q3XyS8Q
QfrsUz2p1fbFicvJwIOJ8B20J/N2/nit4P0gBUTUxv3QEa7XCM/56/xrGkyBzscW
AzBoy/AK9K7GN6z13RozuAS60F1xO7MQc6Yi2VU3eASDQEKiyL/Ubf/s/rkZ+sGj
yJizBACtwCbQzA+z9XBZNUat5NPgcZz5Qeh1nwF9Nxnr6pyBv7tkrLh/3gxRGHqG
063dMbUk8pmUcJzBUyRsNiIPDoEUsLjY5zmZZmp/waAhpREsnK29WLCbqLdpUors
c1JJBsObkA1IM8TZY8YUmvsMEvBLCCanuKpclZZXqeRAeOHJ0v4DAwK8WfuTe5B+
M2BOOeZbN8BpfiA1l//fMMHLRS3UvbLBv4P1+4SyvhyYTR7M76Q0xPc03MFOWHL+
S9VumbQWVGVzdDIgPHRlc3QyQHRlc3QuY29tPohiBBMRAgAiBQJREZ6zAhsDBgsJ
CAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRARJ5QDyxae+MXNAKCzWSDR3tMrTrDb
TAri73N1Xb3j1ACfSl9y+SAah2q7GvmiR1+6+/ekqJGdAVgEURGesxAEANlpMZjW
33jMxlKHDdyRFXtKOq8RreXhq00plorHbgz9zFEWm4VF53+E/KGnmHGyY5Cy8TKy
ZjaueZZ9XuG0huZg5If68irFfNZtxdA26jv8//PdZ0Uj+X6J3RVa2peMLDDswTYL
OL1ZO1fxdtDD40fdAiIZ1QyjwEG0APtz41EfAAMFBAC5/dtgBBPtHe8UjDBaUe4n
NzHuUBBp6XE+H7eqHNFCuZAJ7yqJLGVHNIaQR419cNy08/OO/+YUQ7rg78LxjFiv
CH7IzhfU+6yvELSbgRMicY6EnAP2GT+b1+MtFNa3lBGtBHcJla52c2rTAHthYZWk
fT5R5DnJuQ2cJHBMS9HWyP4DAwK8WfuTe5B+M2C7a/YJSUv6SexdGCaiaTcAm6g/
PvA6hw/FLzIEP67QcQSSTmhftQIwnddt4S4MyJJH3U4fJaFfYQ1zCniYJohJBBgR
AgAJBQJREZ6zAhsMAAoJEBEnlAPLFp74QbMAn3V4857xwnO9/+vzIVnL93W3k0/8
AKC8omYPPomN1E/UJFfXdLDIMi5LoA==
=LSrW
-----END PGP PRIVATE KEY BLOCK-----`

const dsa_elgamal_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xsDiBFERnrMRBADmM0hIfkI3yosjgbWo9v0Lnr3CCE+8KsMszgVS+hBu0XfG
raKmivcA2aaJimHqVYOP7gEnwFAxHBBpeTJcu5wzCFyJwEYqVeS3nnaIhBPp
lSF14Dufi6bB9RV7KxVAg6aunmM2tAutqC+a0y2rDaf7jkJoZ9gWJe2zI+vr
aD6fiwCgxvHo3IgULB9RqIqpLoMgXfcjC+cD/1jeJlKRm+n71ryYwT/ECKss
pFz7S36z6q3XyS8QQfrsUz2p1fbFicvJwIOJ8B20J/N2/nit4P0gBUTUxv3Q
Ea7XCM/56/xrGkyBzscWAzBoy/AK9K7GN6z13RozuAS60F1xO7MQc6Yi2VU3
eASDQEKiyL/Ubf/s/rkZ+sGjyJizBACtwCbQzA+z9XBZNUat5NPgcZz5Qeh1
nwF9Nxnr6pyBv7tkrLh/3gxRGHqG063dMbUk8pmUcJzBUyRsNiIPDoEUsLjY
5zmZZmp/waAhpREsnK29WLCbqLdpUorsc1JJBsObkA1IM8TZY8YUmvsMEvBL
CCanuKpclZZXqeRAeOHJ0s0WVGVzdDIgPHRlc3QyQHRlc3QuY29tPsJiBBMR
AgAiBQJREZ6zAhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRARJ5QD
yxae+MXNAKCzWSDR3tMrTrDbTAri73N1Xb3j1ACfSl9y+SAah2q7GvmiR1+6
+/ekqJHOwE0EURGesxAEANlpMZjW33jMxlKHDdyRFXtKOq8RreXhq00plorH
bgz9zFEWm4VF53+E/KGnmHGyY5Cy8TKyZjaueZZ9XuG0huZg5If68irFfNZt
xdA26jv8//PdZ0Uj+X6J3RVa2peMLDDswTYLOL1ZO1fxdtDD40fdAiIZ1Qyj
wEG0APtz41EfAAMFBAC5/dtgBBPtHe8UjDBaUe4nNzHuUBBp6XE+H7eqHNFC
uZAJ7yqJLGVHNIaQR419cNy08/OO/+YUQ7rg78LxjFivCH7IzhfU+6yvELSb
gRMicY6EnAP2GT+b1+MtFNa3lBGtBHcJla52c2rTAHthYZWkfT5R5DnJuQ2c
JHBMS9HWyMJJBBgRAgAJBQJREZ6zAhsMAAoJEBEnlAPLFp74QbMAn3V4857x
wnO9/+vzIVnL93W3k0/8AKC8omYPPomN1E/UJFfXdLDIMi5LoA==
=Oa9H
-----END PGP PUBLIC KEY BLOCK-----`

const dsa_elgamal_enc_sign_message = `-----BEGIN PGP MESSAGE-----

wcBOA1N4OCSSjECBEAP8DhX4Ii5TxauisNiJ6ThzZVo0rDrM37eG55Z9/Fp9
wOFcMoYiM7muadPd0jjVkGk0Y0d1QrfmAW1619L3kv4lGJcB92jEVXeg6HPq
yLVEc2KzvyIO2ypZ6CBlYhz1iWtc29tgbf1BkVjNGk8C1OIauCqQtNHDwpso
tFF29gfHKbwEAIkeoyCs85tAyJnNWMrEyMo+GSico4uVEiJCw4DD65O4pW3Y
s0PUj9HhE8CY01zKADsn9CHo2P0eppbw/7H++ViHdFzkcbrz6Tqt43tC9B29
NBPdnhMlyJJhivW1FvLoPpuLiYpNb9Dv2lTpug5UUVZR6q9HTuvhP7PJuo5J
3MIh0qsByqXXlrAZuvZtIZVYX9hFLK7AlLQ4BIbJ5ZoTDOMlamviiKEs/Txj
pBbKbBAQW+fw6ajsKSNoWPqYriVEOGtKCfmrCTe32W0Diifyap7VbsY5q9yK
07XbMTDZgtxByDMJ9YLdjG2+J9jkQyKoh8SioWZCeRwsUJOjMTVdfbDAeNId
7me65b7rhtbiR3lU60l5CANdQi+cHTyh3azeFqUqZ5UFNEY8mUXzVWw=
=+rSf
-----END PGP MESSAGE-----`

const p256_pass = ""

const p256_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lHcEWqvIexMIKoZIzj0DAQcCAwTHEN/Yb0iLnIdL1TZcPDB2k+KqSnMlOxiK2YwV
xd9or0tNccGkt7Sg3NcNua7X/YW45Vgkxq0p9lf3pJsepydVAAD/SqMfMs2IAGx3
m0Sv1Jr43iXBQUZiSW+YXfIvqFNm+s8RDrQfdGVzdCB0ZXN0IDxtY3Rlc3R5QGV4
YW1wbGUub3JnPoiQBBMTCAA4FiEECufLSTsSypWIu9QDLSA1IA76sfYFAlqryHsC
GwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQLSA1IA76sfYnfgD+PPwhSbEA
JaE1Vh4UIea7TYAz3XnZp9F8C6B9NWPQWT0A/R0630k5W9uSmdlqP16+LXzs4rdM
bGxSVSBcXVyx9eIWnHsEWqvIexIIKoZIzj0DAQcCAwTwYoek6LUhUSC1ApqXj6xk
CYRH8H+sFLWAcf+P+zMvaR6v49qJl6Y1VYtEgwnpNnQhcx7Vrlul0FkisFqcwfXV
AwEIBwAA/j5HDZp4rZI4KIni08VGpl70oRWdud8zrP8lQpsqZ6n8EYOIeAQYEwgA
IBYhBArny0k7EsqViLvUAy0gNSAO+rH2BQJaq8h7AhsMAAoJEC0gNSAO+rH2hhkA
/14tdEa6SuCtFC0vE+c8pAcs2YNiu3cXDFEyg/3PAUbQAQCOfvI2+mawOH6GJzsz
vhrof7LYUWcOUggO69XoCM9Log==
=bVnA
-----END PGP PRIVATE KEY BLOCK-----`

const p256_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xlIEWqvIexMIKoZIzj0DAQcCAwTHEN/Yb0iLnIdL1TZcPDB2k+KqSnMlOxiK
2YwVxd9or0tNccGkt7Sg3NcNua7X/YW45Vgkxq0p9lf3pJsepydVzR90ZXN0
IHRlc3QgPG1jdGVzdHlAZXhhbXBsZS5vcmc+wpAEExMIADgWIQQK58tJOxLK
lYi71AMtIDUgDvqx9gUCWqvIewIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIX
gAAKCRAtIDUgDvqx9id+AP48/CFJsQAloTVWHhQh5rtNgDPdedmn0XwLoH01
Y9BZPQD9HTrfSTlb25KZ2Wo/Xr4tfOzit0xsbFJVIFxdXLH14hbOVgRaq8h7
EggqhkjOPQMBBwIDBPBih6TotSFRILUCmpePrGQJhEfwf6wUtYBx/4/7My9p
Hq/j2omXpjVVi0SDCek2dCFzHtWuW6XQWSKwWpzB9dUDAQgHwngEGBMIACAW
IQQK58tJOxLKlYi71AMtIDUgDvqx9gUCWqvIewIbDAAKCRAtIDUgDvqx9oYZ
AP9eLXRGukrgrRQtLxPnPKQHLNmDYrt3FwxRMoP9zwFG0AEAjn7yNvpmsDh+
hic7M74a6H+y2FFnDlIIDuvV6AjPS6I=
=UrtO
-----END PGP PUBLIC KEY BLOCK-----`

const p256_enc_sign_message = `-----BEGIN PGP MESSAGE-----

wX4DaAJTyVNTRvUSAgMERFsv0Org2FHPu0n5k6xNOv520Yh2dk2SDojc6cF3
ynPgyMftshAfmDQZ6zPDwW1Ya8EB9ihsXcbjBg4Uf1xoBjCdQHkVTjI39ehZ
fLltFzdpW+HDNL7zx9TjqBi/dWwOIJCSccIb1iOTiCTXTh9X35LSwAMBJtMw
mTOOAKH9hKXOTYIH3EWasWWzSOOqdndYppsiPYBFAUzq9IK07FNU2wb4/Pat
qILTqW783FiECucSCw1gkpWEJVxmh9+gys0JrHLruECY88jK1ujcZL7079gU
546Txtrs8qRso4zCoD/MWwawgdIzdHuRwTo/rwt7jMjMfinZ8/t/CIxyCqva
wLtajClaU5zuD3uGSagSQ6ZZ2ga5Q9XStzZfsuS3yW6qfD/b3Vu3SuRoZGjV
YUjQR2GU+zI4qrw=
=GXt6
-----END PGP MESSAGE-----`

const p384_pass = ""

const p384_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lKQEWqvMThMFK4EEACIDAwQeVELezSIjmPkpfo3QejOWQwPxxaA6xnh3Lgu0zoTz
jbYeE6xFejlLMuHGRs/msuwkqRIEKPufVxDA9t4llIClJus82Bei2FV6gF+21xdI
MynwilwV6hwya6TWWC6sqOMAAX9cMXKSG1fl2yoKM9G95d6+YENwzp5EdOtCKrtL
BOPuEu4yXVNQAxlep0+/MFirWwYWF7QeQmlnIHRlc3QgPEJpZ1Rlc3RAZXhhbXBs
ZS5vcmc+iLAEExMJADgWIQRz2hPLfQfnxiN4c7b9XzwLxz7JSgUCWqvMTgIbAwUL
CQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRD9XzwLxz7JSnyOAYCc0Qm/4TukrxOz
9quCjxjXUC0FJBePOuXjMFHpbRC8/w6Sm/MmL2wv4ogfUlseh2EBgJvUcPmuLG5P
Y/sbpPFa6lkWe9mqWNZA55u8FrO8NhmoT4vpGT/L79PeFZayXR+T0pyoBFqrzE4S
BSuBBAAiAwMEB/yKSJ1l7arWVl3fCt1NmQpGHl3kahzKcymyA0aBisLs9igedPyp
EEnbahUpiwfrQR41hLeL07co/3dceUkcCyuuaJSnR1PrGx/WATvfHVjjFFXJK0L3
lhHwWUISBre+AwEJCQABgN/tAcIomJ3bqh76v8X962P1h/w0W4K9K8F+cypjCm4S
8a0Xfs7oMRTd/FDLU6OB3huKiJgEGBMJACAWIQRz2hPLfQfnxiN4c7b9XzwLxz7J
SgUCWqvMTgIbDAAKCRD9XzwLxz7JSnwTAX9bU7QVcIKnNq15eydUBDsblk0exu0C
epKHjB4WAp8UDKREvG4jhMxlvEa12vWb3yMBgMCjAgQ7WdzJanTZLi6bNyGO3ptg
g++gKRKmxI7Jg0+oAOcL4v2iuUx6Yo66T67gCg==
=CW/l
-----END PGP PRIVATE KEY BLOCK-----`

const p384_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xm8EWqvMThMFK4EEACIDAwQeVELezSIjmPkpfo3QejOWQwPxxaA6xnh3Lgu0
zoTzjbYeE6xFejlLMuHGRs/msuwkqRIEKPufVxDA9t4llIClJus82Bei2FV6
gF+21xdIMynwilwV6hwya6TWWC6sqOPNHkJpZyB0ZXN0IDxCaWdUZXN0QGV4
YW1wbGUub3JnPsKwBBMTCQA4FiEEc9oTy30H58YjeHO2/V88C8c+yUoFAlqr
zE4CGwMFCwkIBwIGFQgJCgsCBBYCAwECHgECF4AACgkQ/V88C8c+yUp8jgGA
nNEJv+E7pK8Ts/argo8Y11AtBSQXjzrl4zBR6W0QvP8OkpvzJi9sL+KIH1Jb
HodhAYCb1HD5rixuT2P7G6TxWupZFnvZqljWQOebvBazvDYZqE+L6Rk/y+/T
3hWWsl0fk9LOcwRaq8xOEgUrgQQAIgMDBAf8ikidZe2q1lZd3wrdTZkKRh5d
5GocynMpsgNGgYrC7PYoHnT8qRBJ22oVKYsH60EeNYS3i9O3KP93XHlJHAsr
rmiUp0dT6xsf1gE73x1Y4xRVyStC95YR8FlCEga3vgMBCQnCmAQYEwkAIBYh
BHPaE8t9B+fGI3hztv1fPAvHPslKBQJaq8xOAhsMAAoJEP1fPAvHPslKfBMB
f1tTtBVwgqc2rXl7J1QEOxuWTR7G7QJ6koeMHhYCnxQMpES8biOEzGW8RrXa
9ZvfIwGAwKMCBDtZ3MlqdNkuLps3IY7em2CD76ApEqbEjsmDT6gA5wvi/aK5
THpijrpPruAK
=DewR
-----END PGP PUBLIC KEY BLOCK-----`

const p384_enc_sign_message = `-----BEGIN PGP MESSAGE-----

wZ4D3tsm495R/DQSAwME/mB7VDjlMWyJzp0BHit9A4M5hFCHSSI70xNeXAqP
+eziDTAoo/J3ulVEVx6dyBvXizBxHIz4F5y8eQPfiz8zgj7572z5kuH+/OIh
+AZzEdIxnH/WkQs9sT9N9ostKXUMMOimh1DXPfEExQ4IFTZDnVEA3fCpFmFO
PzNAArFWk8lM1AaEbu5Z3EPTWQRbY6YSrdLAIwFa2gjuQViUs4akHiCXNq6C
N31ebwBwR/Ax6BKE8H8ruYzNFviz5o6Uw0oDCbaSR9hRTptnA9Hfvr+Dp9XT
/ojG+YYq/gOQSycYB2MrBiIFRkuxwB86Ngq/WNSzMxtsjod4BlCtqmSys9Sj
/D9VySgTdvfBR6ukYMrC0lOgZBkJNtQNuY5qFePTTWQ4s9CdvSKoQQRbUY2V
NWIGuDOafFICpaD5/VQakAemYOCBKks3F+zbHW6M7g/dYt9zZECOCBwrH+1m
ho/jQzANS17yy2O17IXqZUvroDfNjdY8Rw/fiCTL
=cfGW
-----END PGP MESSAGE-----`

const p521_pass = ""

const p521_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lNoEWqvMtxMFK4EEACMEIwQBG+c6zB/CLvG89VPlwcEf7lVw1o/USkR1BKwdEJX+
6kevyCfoW9i5fr3Xj3te/KEkWbm53fYCxQxT1YPCOEQe2/gAyH+Sa+xIL3WFxOho
HLumFLsjhTxI1HO24UNYwrtanYUXJUyZdBdbE3iC0S0pDEVYvCNjNU85tqS5lulh
Mc6xIp0AAgkBlHig6LGOdFTLzkeKJZPTvb//E6lBXuvfbA4plFlg907OM7c6PEUv
noRvR4cNkKDdShJxBPVlZVkbtiMT7H3JmcEgCLQbdGVzdGVyIEEgPHRlc3RAZXhh
bXBsZS5vcmc+iNIEExMKADgWIQSlBvevyCa+SH3t6owrJYFtVTYvDgUCWqvMtwIb
AwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRArJYFtVTYvDn1FAgYuArHX6gpb
FPIo97qMNU+OumyOgzn93w7RzdJUF1Pvyjfib8qAoFc2RbD2B4O10UcFGR/tvY7I
swYU25vwrdpkwQIIy2gvuosOwiHwWOGq7vIPhZX2XiUUCg/IhbbiQVYHMJXgWFuq
m5xbfo5yjBk7fAxyzg2JUbwr5odAGKkXM2zeVFuc3QRaq8y3EgUrgQQAIwQjBAFw
35IH/Ksef/VTf0fuv831HngtCqcW3EBKZT2+eiQcfk6I0mY7fNIHRT2tsc9QBTNk
D5smT8CX9ZnolCOetL9EywBJZp1c3yns6Nk091/K1d9kCLkckRbIm0yS6+/qA0cM
FZZbRfIGHXgyKkG2IZ3diWQIGkYiwx8VtZzmVD/Nx5PhdgMBCgkAAgdbkreSrYh8
5kgEQQsJyLOJVPyS11qqyegmBOOXu4+KDXaKNXeLRszk7mMCdUxLqUeWMrivy0vl
SerrL+aazVYaDCEqiLoEGBMKACAWIQSlBvevyCa+SH3t6owrJYFtVTYvDgUCWqvM
twIbDAAKCRArJYFtVTYvDq2GAgj3HDhyoxdsFkWJ986M7zTijTDHR3D4SVoRu5IB
AsIGDpKBYdYzOEweShT0usxORdha1pIX1M1h8nk6CMm3WHhcxAIHWV9aOdGIhvcT
FBv4c44lu5xpvsgGgmDaIwlgLunElVMnKSXrO9Hqpn9a+pRJv5Be/BsZOW82Y2f7
/K7TUzYNJa4=
=dTWU
-----END PGP PRIVATE KEY BLOCK-----`

const p521_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xpMEWqvMtxMFK4EEACMEIwQBG+c6zB/CLvG89VPlwcEf7lVw1o/USkR1BKwd
EJX+6kevyCfoW9i5fr3Xj3te/KEkWbm53fYCxQxT1YPCOEQe2/gAyH+Sa+xI
L3WFxOhoHLumFLsjhTxI1HO24UNYwrtanYUXJUyZdBdbE3iC0S0pDEVYvCNj
NU85tqS5lulhMc6xIp3NG3Rlc3RlciBBIDx0ZXN0QGV4YW1wbGUub3JnPsLA
EgQTEwoAOBYhBKUG96/IJr5Ife3qjCslgW1VNi8OBQJaq8y3AhsDBQsJCAcC
BhUICQoLAgQWAgMBAh4BAheAAAoJECslgW1VNi8OfUUCBi4CsdfqClsU8ij3
uow1T466bI6DOf3fDtHN0lQXU+/KN+JvyoCgVzZFsPYHg7XRRwUZH+29jsiz
BhTbm/Ct2mTBAgjLaC+6iw7CIfBY4aru8g+FlfZeJRQKD8iFtuJBVgcwleBY
W6qbnFt+jnKMGTt8DHLODYlRvCvmh0AYqRczbN5UW86XBFqrzLcSBSuBBAAj
BCMEAXDfkgf8qx5/9VN/R+6/zfUeeC0KpxbcQEplPb56JBx+TojSZjt80gdF
Pa2xz1AFM2QPmyZPwJf1meiUI560v0TLAElmnVzfKezo2TT3X8rV32QIuRyR
FsibTJLr7+oDRwwVlltF8gYdeDIqQbYhnd2JZAgaRiLDHxW1nOZUP83Hk+F2
AwEKCcK6BBgTCgAgFiEEpQb3r8gmvkh97eqMKyWBbVU2Lw4FAlqrzLcCGwwA
CgkQKyWBbVU2Lw6thgII9xw4cqMXbBZFiffOjO804o0wx0dw+ElaEbuSAQLC
Bg6SgWHWMzhMHkoU9LrMTkXYWtaSF9TNYfJ5OgjJt1h4XMQCB1lfWjnRiIb3
ExQb+HOOJbucab7IBoJg2iMJYC7pxJVTJykl6zvR6qZ/WvqUSb+QXvwbGTlv
NmNn+/yu01M2DSWu
=KibM
-----END PGP PUBLIC KEY BLOCK-----`

const p521_enc_sign_message = `-----BEGIN PGP MESSAGE-----

wcACAzZYNqaBUBrOEgQjBABmhjNT+HfNdK3mVvVRpIbP8BACPUzmnFagNzd7
d4jFqfRrP3Il3ohx+scNEYxFgloGOooukRJXASauk4MUXgvpFAFtycVNTT3N
qgeBQi+j1BLBV53KG+nyxEQRGR9QaDgYjjH0OvyhJbe7Ov9ESwN1nMUH4/Xq
+Zm/vy3/ysRCZ/AYMDAYB238b3OAPjLsAJ+VR6YgJfYK1R4B6+bKM/LufZ7U
N2w6dZtOANXgTfd9JMxIscXSwEUB3YZCrnOsII6ryhkZybjK00n0PRQS4jgK
J8zdv5MvTdYfD3sVPjp7dnZwsuwkipnZEt0l/nMtVvI7l6XnN04RNEK4Elor
D5qRKRI0XcFLaJaZWDh51Lp0kE0iGTkzDI0zhnzh1TY0UyqpTfQ9hvvGWY+s
71oUqUMv3Izq13LUGDFAru9WXxDddATmSZR4PAmUZnHL5cDBK+pLHLjE31c9
IYFwLjDNuBVJ+1BAtP9kvi70j0Nvv7yFfWeeXCN2IFsWe2Mk9108GX5Ls+ta
nmZtITdvQ334bCuvYkxUhdZxZZ4z134uHdqbC0BPtE9ohRUsuhXi+dxXE3Iz
UC6h8O9obgz9IN4=
=/S1e
-----END PGP MESSAGE-----`

const secp256k1_pass = "juliet"

const secp256k1_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

xaIEVjET2xMFK4EEAAoCAwS/zT2gefLhEnISXN3rvdV3eD6MVrPwxNMAR+LM
ZzFO1gdtZbf7XQSZP02CYQe3YFrNQYYuJ4CGkTvOVJSV+yrA/gkDCILD3FP2
D6eRYNWhI+QTFWAGDw+pIhtXQ/p0zZgK6HSk68Fox0tH6TlGtPmtULkPExs0
cnIdAVSMHI+SnZ9lIeAykAcFoqJYIO5p870XbjzNLlJvbWVvIE1vbnRhZ3Vl
IChzZWNwMjU2azEpIDxyb21lb0BleGFtcGxlLm5ldD7CcgQQEwgAJAUCVjET
2wULCQgHAwkQwrEjibQBpD0DFQgKAxYCAQIbAwIeAQAA6McBAMzLoQk8VrIK
AjhlKZmVK57fEVKGP3LqFlMtmo8mq6ylAP4wxPTRrYKJyduGt3XxJBQhhFD/
8juhdWjFk3kwDiuY4cemBFYxE9sSBSuBBAAKAgMEs9mAYLbntFpn0GDeKP06
BKgkbCoi7TdJ9AxOdHZyseQAeotpQibP+XCGwv9Xj33NdnaASZ+goJpyuhc0
MzznFQMBCAf+CQMIqp5StLTK+lBgqmaJ8/64E+8+OJVOgzk8EoRp8bS9IEac
VYu2i8ARjAF3sqwGZ5hxxsniORcjQUghf+n+NwEm9LUWfbAGUlT4YfSIq5pV
rsJhBBgTCAATBQJWMRPbCRDCsSOJtAGkPQIbDAAA5IMBAOAd5crBXv9/ihPz
4AkmZFH8e5+8ZSqjIqq1/lTcj3o/AQDECYLTFXbJUBy6+X4aBp0aLbNyUgtI
9tFEEDilTl2ltw==
=C3TW
-----END PGP PRIVATE KEY BLOCK-----`

const secp256k1_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

xk8EVjET2xMFK4EEAAoCAwS/zT2gefLhEnISXN3rvdV3eD6MVrPwxNMAR+LM
ZzFO1gdtZbf7XQSZP02CYQe3YFrNQYYuJ4CGkTvOVJSV+yrAzS5Sb21lbyBN
b250YWd1ZSAoc2VjcDI1NmsxKSA8cm9tZW9AZXhhbXBsZS5uZXQ+wnIEEBMI
ACQFAlYxE9sFCwkIBwMJEMKxI4m0AaQ9AxUICgMWAgECGwMCHgEAAOjHAQDM
y6EJPFayCgI4ZSmZlSue3xFShj9y6hZTLZqPJquspQD+MMT00a2Cicnbhrd1
8SQUIYRQ//I7oXVoxZN5MA4rmOHOUwRWMRPbEgUrgQQACgIDBLPZgGC257Ra
Z9Bg3ij9OgSoJGwqIu03SfQMTnR2crHkAHqLaUImz/lwhsL/V499zXZ2gEmf
oKCacroXNDM85xUDAQgHwmEEGBMIABMFAlYxE9sJEMKxI4m0AaQ9AhsMAADk
gwEA4B3lysFe/3+KE/PgCSZkUfx7n7xlKqMiqrX+VNyPej8BAMQJgtMVdslQ
HLr5fhoGnRots3JSC0j20UQQOKVOXaW3
=VpL9
-----END PGP PUBLIC KEY BLOCK-----`

const secp256k1_enc_sign_message = `-----BEGIN PGP MESSAGE-----

wX4DDYFqRW5CSpsSAgMEre9Mf7Ig5et7Z+E6dTM/pTEKD8cEIfuW5yV8RL2X
3FqGkGbhpmxgyIrWvf3cJhhmusdkzl+AisnGz71bVgfBYjCfe3olAfyvlZUj
0Bf0pPh9EfdD5dFLf5XXXkXdOwuUeW6UffdrYA14avHkjqmoE9fSwAMBc4Pm
EiOLe7iNZgYtTzvCXei213SCdN17sixw5c/iroY1QuFwECMdlQG0X9qG4Ddp
JCnW+dPZ9lHCD+NyaWoY3QAAMyMTlMeysj19o7LHG4+fgUZL2XBGcrnZkgmF
i4YsT9fLuVf/cPPnBI+grrQPNEzZim1FgBjcgD7QgoPbrATtq63lEyJbjwAw
KC38/emOZdwHe3RyhJSFdJ0B6VVz9nJuYvncE1VkuZVxaRhtE2FmZutBC/cy
UMcIpI0EsrGSCI8=
=8BUx
-----END PGP MESSAGE-----`

const ed25519_pass = "sun"

const ed25519_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lIYEWkN+5BYJKwYBBAHaRw8BAQdAIGqj23Kp273IPkgjwA7ue5MDIRAfWLYRqnFy
c2AFMcD+BwMCeaL+cNXzgI7uJQ7HBv53TAXO3y5uyJQMonkFtQtldL8YDbNP3pbd
3zzo9fxU12bWAJyFwBlBWJqkrxZN+0jt0ElsG3kp+V67MESJkrRhKrQRTGlnaHQg
PGxpZ2h0QHN1bj6IkAQTFggAOBYhBIZLQa5UQtPdGzTChx7N8CbAJFgwBQJaQ37k
AhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEB7N8CbAJFgwu14BAIVlyXyQ
HEIfzrCaqlzb4q0QDyX+Gx+HuN34la7IW65EAPsE6LHxWjU/+G/ypRjBKfchFc94
Ze5yhZWgoaDFF37MA5yLBFpDfuQSCisGAQQBl1UBBQEBB0AvUqQcIXG0rUKC9mUi
dP/Lo5B4J9eJjN3+Ljna3ZlHYAMBCAf+BwMCvyW2D5Yx6dbujE3yHi1XQ9MbhOY5
XRFFgYIUYzzi1qmaL+8Gr9zODsUdeO60XHnMXOmqVa6/sdx32TWo5s3sgS19kRUM
D+pbxS/aZnxvrYh4BBgWCAAgFiEEhktBrlRC090bNMKHHs3wJsAkWDAFAlpDfuQC
GwwACgkQHs3wJsAkWDCe9QEA5qEE4N+qX465fNrK0ulz0ScZd6/+paVhmjYo9Fab
QdsBANlddInzoZ8CCwsNagZXujp+2gWtue5axTPnDkjGhLIK
=wo91
-----END PGP PRIVATE KEY BLOCK-----`

const ed25519_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEWkN+5BYJKwYBBAHaRw8BAQdAIGqj23Kp273IPkgjwA7ue5MDIRAfWLYRqnFy
c2AFMcC0EUxpZ2h0IDxsaWdodEBzdW4+iJAEExYIADgWIQSGS0GuVELT3Rs0woce
zfAmwCRYMAUCWkN+5AIbAwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRAezfAm
wCRYMLteAQCFZcl8kBxCH86wmqpc2+KtEA8l/hsfh7jd+JWuyFuuRAD7BOix8Vo1
P/hv8qUYwSn3IRXPeGXucoWVoKGgxRd+zAO4OARaQ37kEgorBgEEAZdVAQUBAQdA
L1KkHCFxtK1CgvZlInT/y6OQeCfXiYzd/i452t2ZR2ADAQgHiHgEGBYIACAWIQSG
S0GuVELT3Rs0wocezfAmwCRYMAUCWkN+5AIbDAAKCRAezfAmwCRYMJ71AQDmoQTg
36pfjrl82srS6XPRJxl3r/6lpWGaNij0VptB2wEA2V10ifOhnwILCw1qBle6On7a
Ba257lrFM+cOSMaEsgo=
=D8HS
-----END PGP PUBLIC KEY BLOCK-----`

const ed25519_enc_sign_message = `-----BEGIN PGP MESSAGE-----

wV4DzYfy+90rz7YSAQdAWBKmhkgx+WtyERt903WpExRZfyAhxji8FKhthTRI
Lw4w/vzk9zMULlXZSknznkPnRlJyFUHqH9gFt8e3EQlij62Kd5T5AQBc0CLC
fLZzou7u0sADAdWRcTHqdoIZCDgbJQEW3kbZOP9kEliyrB2K1UYYgOnGyLe2
xpZd5f14Lfieb/CyO+BoqCpRSKJFSuMo7V+MY/mpt/liEMDPr+aRsOlyf+KE
i9OznbgOX1oXdHbyodjTe9H7OxgFi/BxH6zQlFhxappmD5I3fmp1/ONvfXf/
KN5U4Rx7ftKgsaTMsEnKk/w8rEqxL8a1YtLe4X1tdecRBTi7qbndYeXp5lVl
+tnmmywmjXk+mx/l+NluOga79j7pZ0zO
=Co9x
-----END PGP MESSAGE-----`

const brainpool_testmessage = `test問量鮮控到案進平
`

const brainpoolp256r1_pass = ""

const brainpoolp256r1_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lHgEWrpD4RMJKyQDAwIIAQEHAgMEMyiJsl3MxlZFRRg518IiUbv+/294KU+dBq/B
QYbvt4dHh4M7O9Rgfic8EPbe47wKr6v6Z7wXgHpjqtKRoBzlxAAA/jhgOEGBKP4E
IRHwnwkFI5FRIf6A+R9oZQ0kay8/+xNCDGy0HXRlc3RAZ29jcnlwdG8gPHRlc3RA
Z29jcnlwdG8+iJAEExMIADgWIQTWZQHprbRVRe9D5xkELYRs3suJpAUCWrpD4QIb
AwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRAELYRs3suJpGVgAP48h9xGECGF
L87pAJSRedg//d+ucwcWTRpblHskV59+HgD/T5DvU4AfmKvYUyhfkhLkqU+g2HO+
dGU+/maeQymZBmycfARaukPhEgkrJAMDAggBAQcCAwQfD3jLYinp+eI5OjtwPhPs
GYO/OtUhD8T9dyVJL306RgZyrtO2lwwEM3S/bN5F0lymte5XddH2wkt6Gv3stGV2
AwEIBwAA/0vEs+P6LCQMFoxePlHi5kNvbuX0UH8YK8dAtsiY/LC3EdyIeAQYEwgA
IBYhBNZlAemttFVF70PnGQQthGzey4mkBQJaukPhAhsMAAoJEAQthGzey4mk44wA
/0CN2zUDoUEeVN1XouqbKgr9AxG/ffrZkvZDt4irMycOAP40NcvlLSUHrO6XQZPA
gTHjrXXT++KbkzQRVWMO8UpRwg==
=BkRB
-----END PGP PRIVATE KEY BLOCK-----`

const brainpoolp256r1_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mFMEWrpD4RMJKyQDAwIIAQEHAgMEMyiJsl3MxlZFRRg518IiUbv+/294KU+dBq/B
QYbvt4dHh4M7O9Rgfic8EPbe47wKr6v6Z7wXgHpjqtKRoBzlxLQddGVzdEBnb2Ny
eXB0byA8dGVzdEBnb2NyeXB0bz6IkAQTEwgAOBYhBNZlAemttFVF70PnGQQthGze
y4mkBQJaukPhAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEAQthGzey4mk
ZWAA/jyH3EYQIYUvzukAlJF52D/9365zBxZNGluUeyRXn34eAP9PkO9TgB+Yq9hT
KF+SEuSpT6DYc750ZT7+Zp5DKZkGbLhXBFq6Q+ESCSskAwMCCAEBBwIDBB8PeMti
Ken54jk6O3A+E+wZg7861SEPxP13JUkvfTpGBnKu07aXDAQzdL9s3kXSXKa17ld1
0fbCS3oa/ey0ZXYDAQgHiHgEGBMIACAWIQTWZQHprbRVRe9D5xkELYRs3suJpAUC
WrpD4QIbDAAKCRAELYRs3suJpOOMAP9Ajds1A6FBHlTdV6LqmyoK/QMRv3362ZL2
Q7eIqzMnDgD+NDXL5S0lB6zul0GTwIEx46110/vim5M0EVVjDvFKUcI=
=Bx7J
-----END PGP PUBLIC KEY BLOCK-----`

const brainpoolp256r1_enc_sign_message = `-----BEGIN PGP MESSAGE-----

hH4DLFUmpfJ2kxcSAgMElfY0YbA1dI8s8MMhBHOXw0wwR/O+S8Pm/huBbkIbOb2c
AL7ImXZYvPgS5tkpbxmItEedlLF439E8rwrPBqmrWTDSy/q9CyR2IKVSVNbConaz
lyGGvVXNmGZm1jH2tDKAxqSGMUtuz4x6rgSqThRplSrSwBcBLd8NKo+3Q04AlSVf
MdX0IZ3iualEff4RzpAwKdNO7V/y3z4Syhs2ZfXNGvt+F5Hnr9+PWnUcjQWUeWxS
Z81hIqHWQ6paPBkM05I1P+zWuYF56UK7DGBIASBIJXaPclK1YoQ+o9ceChk9T6uy
u3mju+/L4V2CAoY+G8DX3PtU6eFc+wVoyKFdEE9sjkVTbjK1zYqjlTR4R0zckX+L
diQ5YxtNVswo92sg9wpD93+EN7YSFx9ZlC7JrRSlf0betdX4iQ4VO8lG2FahgcYI
wyZAsOwGJD4+TQ==
=GeXG
-----END PGP MESSAGE-----`

const brainpoolp384r1_pass = ""

const brainpoolp384r1_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lKgEWrqJ2RMJKyQDAwIIAQELAwMELWPYFx5PjaQLkP/dNEmMYqD72jsx/IzSO9j1
FsmwE7hmosHMjXcDWrsxDuRqPfFMN98P/8kRB4Qn+o2dNHHdRuzAm/O5XCpoFGRL
PJ7nIFn/DMf6gmFUxDZYwxbWiK2QAAF+NpeKlJvJr2gDf/d2DaRjwOCXCjUnOQuo
+XQAKlEp8SG3LRhnD9E/bKG4q3JHcH1jFY+0InRlc3QzODRAZ29jcnlwdG8gPHRl
c3QzODRAZ29jcnlwdD6IsAQTEwkAOBYhBPD66ZJLMNNU+RLWJOJ39qEi22ymBQJa
uonZAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEOJ39qEi22ym1dwBfi1T
e1FIGoDOWl6pFY1n92Fuur4m5gJKiZ+f1Sh2ZsyE8mfxqloSZsERKx4KEVZCgwF8
DHhvCatkh/WrEE2RXGO9fRnLXZGKGYbwuXAXDFa/cJJ+bUIDu/epm/4ge7E+X7NW
nKwEWrqJ2RIJKyQDAwIIAQELAwMEh3cON/Xg5LSr6T9iMqgtVEIW8eAoCfi+p8NS
4Xr+OLcEX6PhcY5lTKUZEf0zBqVMAn4yw12W389gJEzcwEq+eoyG5FYetezdhC8Z
e+df1Ha7nnLY0TWBjTvNEnxdgx2YAwEJCQABf2uXve5jHifo/pNRLy7vXFNYN2zJ
w7GSYvY35hmx5OjiM8HkDSYom1UB125p1b+/EhmIiJgEGBMJACAWIQTw+umSSzDT
VPkS1iTid/ahIttspgUCWrqJ2QIbDAAKCRDid/ahIttspozuAX437euAjbm+goCs
bWXr9j8+oRRK56CODQrwjGCdjeyFP/wEHjV96ZbBBLAspykPwL0Bf3FgnJe/mxFU
MfjeXWX2rg7rPiWO9HU41dsEcZ2pvN3sC5mQchfqivFINTvIngmk2g==
=8J0V
-----END PGP PRIVATE KEY BLOCK-----`

const brainpoolp384r1_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mHMEWrqJ2RMJKyQDAwIIAQELAwMELWPYFx5PjaQLkP/dNEmMYqD72jsx/IzSO9j1
FsmwE7hmosHMjXcDWrsxDuRqPfFMN98P/8kRB4Qn+o2dNHHdRuzAm/O5XCpoFGRL
PJ7nIFn/DMf6gmFUxDZYwxbWiK2QtCJ0ZXN0Mzg0QGdvY3J5cHRvIDx0ZXN0Mzg0
QGdvY3J5cHQ+iLAEExMJADgWIQTw+umSSzDTVPkS1iTid/ahIttspgUCWrqJ2QIb
AwULCQgHAgYVCAkKCwIEFgIDAQIeAQIXgAAKCRDid/ahIttsptXcAX4tU3tRSBqA
zlpeqRWNZ/dhbrq+JuYCSomfn9UodmbMhPJn8apaEmbBESseChFWQoMBfAx4bwmr
ZIf1qxBNkVxjvX0Zy12RihmG8LlwFwxWv3CSfm1CA7v3qZv+IHuxPl+zVrh3BFq6
idkSCSskAwMCCAEBCwMDBId3Djf14OS0q+k/YjKoLVRCFvHgKAn4vqfDUuF6/ji3
BF+j4XGOZUylGRH9MwalTAJ+MsNdlt/PYCRM3MBKvnqMhuRWHrXs3YQvGXvnX9R2
u55y2NE1gY07zRJ8XYMdmAMBCQmImAQYEwkAIBYhBPD66ZJLMNNU+RLWJOJ39qEi
22ymBQJauonZAhsMAAoJEOJ39qEi22ymjO4Bfjft64CNub6CgKxtZev2Pz6hFErn
oI4NCvCMYJ2N7IU//AQeNX3plsEEsCynKQ/AvQF/cWCcl7+bEVQx+N5dZfauDus+
JY70dTjV2wRxnam83ewLmZByF+qK8Ug1O8ieCaTa
=vEH0
-----END PGP PUBLIC KEY BLOCK-----`

const brainpoolp384r1_enc_sign_message = `-----BEGIN PGP MESSAGE-----

hJ4D25491by3UQcSAwMEidpiLdDr/FBd9HVhN1kjJkagjbXQrKPuu47ws2k67MBS
gNo913vEQOzhqdiVliYtMAIpEt4sNyWCQ+TUEigsFiaG6Dp0wPG4/qVhRgRB4poN
jyIOvcTkW+Ze8m5wjUHJMIuUlrcUhDKpTRUiWaCuMG099YhTndV/vHHLJLAgyn3r
GTmT6CnwHwtrbikJAC/I09LAOgGlDrS761lbkUbWm64Zl6Tqa56ioZVe1rEXB1aG
x8uoraH9XwrKBu99KBnXegez3NBmb8V9r1ZJ6WTYN8QnIrtZCwI2ssdNLuQRZJU3
X/D1ZeEkQO/125Df/df5vfR9J7Vmg5R1cJ03AEv4apu3P+P8PdvONF0Xr82ZX7++
sLfK22tMrP1W0+mxnvu45B9Gz7ymT+2kLu6iyuvAW17IkC0yUqn7Js6XdDpFk/h7
u5G2RTWbD9Zhdmv0p8MqpvTb8DugOTjwXxWa6Mr384O0btojdAV2+T3FBko45ubV
bmKARW86AH7YpKjCbedsy9e5SvQohv102w/mZVk=
=C5uY
-----END PGP MESSAGE-----`

const brainpoolp512r1_pass = ""

const brainpoolp512r1_priv = `-----BEGIN PGP PRIVATE KEY BLOCK-----

lNgEWrqKjRMJKyQDAwIIAQENBAMEDI4HTYTe2L0kzVVIJUrN7+8KivNLQNRUeLFp
oeKHeEqZdzv2zuYsqW91wTcxuobHuyhz2Rw/6GuxCjHMZKe1OEKzO73MHvk5x3Ut
gsU3ziA4GYM1fPJobOJXwEvB7Hdt1jPnX6FDzsnnDb/V08o7oRDiFF+nakbZ4fdh
BGPtoO8AAf94HXntn7GFtPoPKEG4GjDchW7kLoi99khL4afe/rEuuWDT4ue/osUw
gDxddaBV2HpYlJtljbALvS+Fqlaz6+7mJOG0InRlc3Q1MTJAZ29jcnlwdG8gPHRl
c3Q1MTJAZ29jcnlwdD6I0AQTEwoAOBYhBFZP0ImPk6gNK4o9sl/7WVyCi79OBQJa
uoqNAhsDBQsJCAcCBhUICQoLAgQWAgMBAh4BAheAAAoJEF/7WVyCi79OH2YCAIdC
LCIm4/8dTT3RROYFK/ERghCXH6Q42U5ojGdVc4+HSLiWyUijjqSznhrRtY4Izfcd
23eLZCo1TjvfPWsK8N0B/1eRbHersapjqA2jhHjbhGr6pyZhmBZtMpeqJ80R86Ka
cFcRH008VrqJoZwSRt+BQHDdwiWG+ZQiTY8Y9KmZ5pSc3ARauoqNEgkrJAMDAggB
AQ0EAwQ0T5L5YcJMUFF8OYFvHlwcym3o3APGsbUCvfhUguYWOyEr9drNiYCaC0gl
bO+KackLO30gWiVg1gHY3CoJfi0kRwt1tXKkiqh7wCD2BPDzP0lhF3nHaAKNpg3h
mpGUcZui9FyTezwK6CjqBgAhLETCwevB1MXQuvvPgw9uil7rbQMBCgkAAf96G+z/
K9vrz/nhvZessIeGAEHhmrGkHLBpw+9IGDs7hWNvisTn99JezTtPbYMInrwmEOB9
9VoAIO8Xrom5XFXjI42IuAQYEwoAIBYhBFZP0ImPk6gNK4o9sl/7WVyCi79OBQJa
uoqNAhsMAAoJEF/7WVyCi79O3QIB/1e/HKOHV7504x0wu14qXDN+2QW8P6j8d0qI
GB7xOegf8Z8KgzGywZFjTT6GKBqPTz2vMd4u44/sLBVBgPgiKQgB/308ETfQaPcz
ctjlrmykdX0TrdiKLy92xAqsohFff5Ri5pr500005rTYJfNYN+Cug6u9UygWL2RY
u4H95mtsxZo=
=Qb7k
-----END PGP PRIVATE KEY BLOCK-----`

const brainpoolp512r1_pub = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mJMEWrqKjRMJKyQDAwIIAQENBAMEDI4HTYTe2L0kzVVIJUrN7+8KivNLQNRUeLFp
oeKHeEqZdzv2zuYsqW91wTcxuobHuyhz2Rw/6GuxCjHMZKe1OEKzO73MHvk5x3Ut
gsU3ziA4GYM1fPJobOJXwEvB7Hdt1jPnX6FDzsnnDb/V08o7oRDiFF+nakbZ4fdh
BGPtoO+0InRlc3Q1MTJAZ29jcnlwdG8gPHRlc3Q1MTJAZ29jcnlwdD6I0AQTEwoA
OBYhBFZP0ImPk6gNK4o9sl/7WVyCi79OBQJauoqNAhsDBQsJCAcCBhUICQoLAgQW
AgMBAh4BAheAAAoJEF/7WVyCi79OH2YCAIdCLCIm4/8dTT3RROYFK/ERghCXH6Q4
2U5ojGdVc4+HSLiWyUijjqSznhrRtY4Izfcd23eLZCo1TjvfPWsK8N0B/1eRbHer
sapjqA2jhHjbhGr6pyZhmBZtMpeqJ80R86KacFcRH008VrqJoZwSRt+BQHDdwiWG
+ZQiTY8Y9KmZ5pS4lwRauoqNEgkrJAMDAggBAQ0EAwQ0T5L5YcJMUFF8OYFvHlwc
ym3o3APGsbUCvfhUguYWOyEr9drNiYCaC0glbO+KackLO30gWiVg1gHY3CoJfi0k
Rwt1tXKkiqh7wCD2BPDzP0lhF3nHaAKNpg3hmpGUcZui9FyTezwK6CjqBgAhLETC
wevB1MXQuvvPgw9uil7rbQMBCgmIuAQYEwoAIBYhBFZP0ImPk6gNK4o9sl/7WVyC
i79OBQJauoqNAhsMAAoJEF/7WVyCi79O3QIB/1e/HKOHV7504x0wu14qXDN+2QW8
P6j8d0qIGB7xOegf8Z8KgzGywZFjTT6GKBqPTz2vMd4u44/sLBVBgPgiKQgB/308
ETfQaPczctjlrmykdX0TrdiKLy92xAqsohFff5Ri5pr500005rTYJfNYN+Cug6u9
UygWL2RYu4H95mtsxZo=
=3o0a
-----END PGP PUBLIC KEY BLOCK-----`

const brainpoolp512r1_enc_sign_message = `-----BEGIN PGP MESSAGE-----

hL4DpJcoPAigmZESBAMEonrXiHjcMR/PE/ZwHEfC2rqhzugPOjxoytUCFx/WwLyI
hREwlk3QA4wKO/xM9bgIkUg9bVlbJtsGceAcDgzxPonaeP+UhEMpi+otV4NT9y/F
DPtdGCzM+n4rYHUzJqC5reyzjDbadiiV81YKoY67ZPulMwpqvZbCq1z9p0Qvpyww
M4Tk2YJP1seL0WlcM3Tt7i0ZmegAa53OopqNLz5Mopba+f1aQOJeg8poY7xeR6Rq
0sBaAf1vfSsrWQgBFxYwTWLtzysuls4l2h/xGoa2Ril9kAz0AZ7I3XdrXiaSkPAJ
wkOI7zAdKE9urG0ZqsomInQq+u3RPQ349zms7B/+VttAlAg8WDKMDcNcFvPFDN85
UACHO5UciN3682snpVmETKIo7jFXHj4ie9ITzpk/3MmWxvqbe1MiS1lQrRMY5PWL
j9JULeBESodavfg2Mcf5tWGS7bMn/shojxbaYORZi70dw0Cl/e9Noh1hUeBd6ip6
VkwhyLHSTB5tIq5pKSlNhgkuJDEhVvHsbFRjoioetH7hRkV4yolSWxB5iMT0lD1+
KEKKTcNt1VHJ1cgSKi+S/fGYvHIPt1C2mXK1EBOqzJhVJxR8GNF3jF2aYG2r
=zG+7
-----END PGP MESSAGE-----`
