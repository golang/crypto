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
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"hash"
	"testing"
	"time"
)

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

func TestPrivateKeyRead(t *testing.T) {
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

func populateHash(hashFunc crypto.Hash, msg []byte) (hash.Hash, error) {
	h := hashFunc.New()
	if _, err := h.Write(msg); err != nil {
		return nil, err
	}
	return h, nil
}

func TestRSAPrivateKey(t *testing.T) {
	privKeyDER, _ := hex.DecodeString(pkcs1PrivKeyHex)
	rsaPriv, err := x509.ParsePKCS1PrivateKey(privKeyDER)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := NewRSAPrivateKey(time.Now(), rsaPriv).Serialize(&buf); err != nil {
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
	msg := []byte("Hello World!")

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

func TestECDSAPrivateKey(t *testing.T) {
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
	msg := []byte("Hello World!")

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

func TestRSASignerPrivateKey(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}

	priv := NewSignerPrivateKey(time.Now(), &rsaSigner{rsaPriv})

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}
	msg := []byte("Hello World!")

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

type ecdsaSigner struct {
	*ecdsa.PrivateKey
}

func TestECDSASignerPrivateKey(t *testing.T) {
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
	msg := []byte("Hello World!")

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

func TestIssue11505(t *testing.T) {
	// parsing a rsa private key with p or q == 1 used to panic due to a divide by zero
	_, _ = Read(readerFromHex("9c3004303030300100000011303030000000000000010130303030303030303030303030303030303030303030303030303030303030303030303030303030303030"))
}

func TestPrivateKeyEncrypt(t *testing.T) {
	packet, err := Read(readerFromHex(privKeyRSAClearHex))
	if err != nil {
		t.Errorf("failed to parse: %s", err)
		return
	}

	privKey := packet.(*PrivateKey)

	err = privKey.Encrypt([]byte("testing"), nil)
	if err != nil {
		t.Errorf("failed to encrypt: %s", err)
		return
	}

	if !privKey.Encrypted || privKey.PrivateKey != nil {
		t.Error("bad result, key not encrypted")
	}

	var buf bytes.Buffer
	err = privKey.Serialize(&buf)
	if err != nil {
		t.Errorf("failed to serialize encrypted key: %s", err)
	}

	p, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}

	priv, ok := p.(*PrivateKey)
	if !ok {
		t.Fatal("didn't parse private key")
	}

	err = priv.Decrypt([]byte("testing"))
	if err != nil {
		t.Errorf("failed to decrypt key: %s", err)
		return
	}

	sig := &Signature{
		PubKeyAlgo: PubKeyAlgoRSA,
		Hash:       crypto.SHA256,
	}
	msg := []byte("Hello World!")

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

// Generated with `gpg --export-secret-keys "Test Key 2"`
const privKeyRSAHex = "9501fe044cc349a8010400b70ca0010e98c090008d45d1ee8f9113bd5861fd57b88bacb7c68658747663f1e1a3b5a98f32fda6472373c024b97359cd2efc88ff60f77751adfbf6af5e615e6a1408cfad8bf0cea30b0d5f53aa27ad59089ba9b15b7ebc2777a25d7b436144027e3bcd203909f147d0e332b240cf63d3395f5dfe0df0a6c04e8655af7eacdf0011010001fe0303024a252e7d475fd445607de39a265472aa74a9320ba2dac395faa687e9e0336aeb7e9a7397e511b5afd9dc84557c80ac0f3d4d7bfec5ae16f20d41c8c84a04552a33870b930420e230e179564f6d19bb153145e76c33ae993886c388832b0fa042ddda7f133924f3854481533e0ede31d51278c0519b29abc3bf53da673e13e3e1214b52413d179d7f66deee35cac8eacb060f78379d70ef4af8607e68131ff529439668fc39c9ce6dfef8a5ac234d234802cbfb749a26107db26406213ae5c06d4673253a3cbee1fcbae58d6ab77e38d6e2c0e7c6317c48e054edadb5a40d0d48acb44643d998139a8a66bb820be1f3f80185bc777d14b5954b60effe2448a036d565c6bc0b915fcea518acdd20ab07bc1529f561c58cd044f723109b93f6fd99f876ff891d64306b5d08f48bab59f38695e9109c4dec34013ba3153488ce070268381ba923ee1eb77125b36afcb4347ec3478c8f2735b06ef17351d872e577fa95d0c397c88c71b59629a36aec"

// Generated by `gpg --export-secret-keys` followed by a manual extraction of
// the ElGamal subkey from the packets.
const privKeyElGamalHex = "9d0157044df9ee1a100400eb8e136a58ec39b582629cdadf830bc64e0a94ed8103ca8bb247b27b11b46d1d25297ef4bcc3071785ba0c0bedfe89eabc5287fcc0edf81ab5896c1c8e4b20d27d79813c7aede75320b33eaeeaa586edc00fd1036c10133e6ba0ff277245d0d59d04b2b3421b7244aca5f4a8d870c6f1c1fbff9e1c26699a860b9504f35ca1d700030503fd1ededd3b840795be6d9ccbe3c51ee42e2f39233c432b831ddd9c4e72b7025a819317e47bf94f9ee316d7273b05d5fcf2999c3a681f519b1234bbfa6d359b4752bd9c3f77d6b6456cde152464763414ca130f4e91d91041432f90620fec0e6d6b5116076c2985d5aeaae13be492b9b329efcaf7ee25120159a0a30cd976b42d7afe030302dae7eb80db744d4960c4df930d57e87fe81412eaace9f900e6c839817a614ddb75ba6603b9417c33ea7b6c93967dfa2bcff3fa3c74a5ce2c962db65b03aece14c96cbd0038fc"

// pkcs1PrivKeyHex is a PKCS#1, RSA private key.
// Generated by `openssl genrsa 1024 | openssl rsa -outform DER  | xxd -p`
const pkcs1PrivKeyHex = "3082025d02010002818100e98edfa1c3b35884a54d0b36a6a603b0290fa85e49e30fa23fc94fef9c6790bc4849928607aa48d809da326fb42a969d06ad756b98b9c1a90f5d4a2b6d0ac05953c97f4da3120164a21a679793ce181c906dc01d235cc085ddcdf6ea06c389b6ab8885dfd685959e693138856a68a7e5db263337ff82a088d583a897cf2d59e9020301000102818100b6d5c9eb70b02d5369b3ee5b520a14490b5bde8a317d36f7e4c74b7460141311d1e5067735f8f01d6f5908b2b96fbd881f7a1ab9a84d82753e39e19e2d36856be960d05ac9ef8e8782ea1b6d65aee28fdfe1d61451e8cff0adfe84322f12cf455028b581cf60eb9e0e140ba5d21aeba6c2634d7c65318b9a665fc01c3191ca21024100fa5e818da3705b0fa33278bb28d4b6f6050388af2d4b75ec9375dd91ccf2e7d7068086a8b82a8f6282e4fbbdb8a7f2622eb97295249d87acea7f5f816f54d347024100eecf9406d7dc49cdfb95ab1eff4064de84c7a30f64b2798936a0d2018ba9eb52e4b636f82e96c49cc63b80b675e91e40d1b2e4017d4b9adaf33ab3d9cf1c214f024100c173704ace742c082323066226a4655226819a85304c542b9dacbeacbf5d1881ee863485fcf6f59f3a604f9b42289282067447f2b13dfeed3eab7851fc81e0550240741fc41f3fc002b382eed8730e33c5d8de40256e4accee846667f536832f711ab1d4590e7db91a8a116ac5bff3be13d3f9243ff2e976662aa9b395d907f8e9c9024046a5696c9ef882363e06c9fa4e2f5b580906452befba03f4a99d0f873697ef1f851d2226ca7934b30b7c3e80cb634a67172bbbf4781735fe3e09263e2dd723e7"

// Generated with `gpg --export-secret-keys "Clear Test Key 2"
const privKeyRSAClearHex = "9501d8045febc1c9010400cde5b1a561947b557644cfbada12f245fe88671e0b8366f0496f7b2b9fc0ef576f3f63e5436b50f276598c8681d82b2778886dc879d3834aec2fbb4e71b292040252d9f55cec38d56f92a556ad9acaf05bef65d2387a5bfa49eeb5f3f7d8a965e39993bfdc5b1afb0791e94f304df361cfac81dbebf54fc8a571b3b3e2af886900110100010003fc0ac06d15a002172ba80ca1555648697ed6b30c417123f836e17ad1117edade14b0823ca6eeed967146d557c57957ceaf15b7f815a128f6a0edb2f362be04af63aea66bfb19fd99cf48d2370c22caff9fe2b69dc34a2b9f775d6007810ab44c4b67242ba03b5b8bb79f1030eecc53b3c8385159c3bb8c35ffaa8f25319b44a3410200d3ece244675a994ef2aad7e16cab93148a1f13aa9fda435c78d0ee7fe543822bbb07ff3f6ec0af167ef8a885cab7a9e045199422c2de725664c0017a3f7c9fc90200f8b7de67d23a2c3dc96972e17d3785e37637244019852ccbc23cf684d4f96dca4fcc567a2ee56d18853f185b0a6675cbd095f3b85a08d1266f164a18d6aa33a101fe272ddd9abac119427da0cb3735f1d8ee2b2d128c69ae9da8ae62221033d8a155c0fb5c940537f5b58d5c84c5b6a9127b5443222af526ca719570575c922ad55da1cbb41c436c6561722054657374204b65792032203c636c656172406b65793e88cd0413010a0038162104e255b46597e26e5d412071c056fa5a5010b5460a05025febc1c9021b03050b0908070206150a09080b020416020301021e01021780000a091056fa5a5010b5460a2acd03f76a8ccf32c35884092c3681ab35c620e44189cea0b7df99003a87ab96e5ef777eda91f5cf43b54a456aabb3ffbbff9349fcd8d010e988fb245d74087a6e402ae6b295cfbce7e5f4dc93752e642b8c4dc883ab924b85a76c58353e7c1d6e0f536315086f47000aee85cbc1de32beddc7e8b2b9efc72b32a0c9ff37751c0f915c9d01d8045febc1c9010400cf67da136be24e210b8a3bbf9cdb86c6a1e51ef0f5bc93ce288019d709c5506ceab9bf8f79415949f2b51c7725943f932343bf11e88f5c1d01f675f423d7ad14bdaa22dea1293fd2526cbc2e492a278b69a2e7e0cf057091b4fa6323fc2a6881519f932fe8751afb71d2255d04825a3f41a0a4674a88b6651cfd13c46f649b5900110100010003fd1edc558b1140ed9e2620ededff717cb6de8d00931b0571bab9b501e348cd66bfa6177864e9466b7a40d669036380910b1c32aee203c81d0d25e71dbaf3805a7cd828ecd674088c885dd02c434326c86b82f70b6d394813a679805f2bc056c6f4a8460cb149dde30e5aff48d7dade90c8f9c8875eba74477276eba2bc7e4a57990200d0afab1c2d468876ad4f47cd59101962a12861c6889ac073896cd2d5e820d4e627b79c4fccc6ca81788c11fe026667a10db7a9a7f09a48dbb198fec9c99dc2ed0200fe6ddc3450065a235672e4158e747416ebe0e27a49a34d90aa7602c31913bddc6bcb4c332b488933939b95760a036273b625e1867aead21dc9cab6239662509d01ff78e06b98913dd5536f390533a354658b99d72f6b57bc104f09cd2135688e095bf1297928d9ac476a685cece1266a7a63c3170478dbe7e772f09d87ed3799be2ba0ff88b60418010a0020162104e255b46597e26e5d412071c056fa5a5010b5460a05025febc1c9021b0c000a091056fa5a5010b5460acebf03ff47f6b4e90996b7357ec30b3d2c82f663d689172b63eb8ff35207991f032f77708a28e9bcdea4d2995f4f06e4aa5570714360716e0f931cee47151ae7c3829dc12524b78209509c7351421efd1861b0871d2b23638094570d87a5439d05f245cafab5e347ec37be2c534091453c13fd3019841e1c69352ab80c6db7ada4fcddc1"
