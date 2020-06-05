package openpgp

import (
	"bytes"
	"crypto"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/internal/algorithm"
)

var hashes = []crypto.Hash{
	crypto.MD5,
	crypto.SHA1,
	crypto.SHA224,
	crypto.SHA256,
	crypto.SHA384,
	crypto.SHA512,
}

var ciphers = []packet.CipherFunction{
	packet.Cipher3DES,
	packet.CipherCAST5,
	packet.CipherAES128,
	packet.CipherAES192,
	packet.CipherAES256,
}

var aeadModes = []packet.AEADMode{
	packet.AEADModeEAX,
	packet.AEADModeOCB,
}

func TestKeyExpiry(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(expiringKeyHex))
	if err != nil {
		t.Fatal(err)
	}
	entity := kring[0]

	const timeFormat = "2006-01-02"
	time1, _ := time.Parse(timeFormat, "2013-07-02")

	// The expiringKeyHex key is structured as:
	//
	// pub  1024R/5E237D8C  created: 2013-07-01                      expires: 2013-07-31  usage: SC
	// sub  1024R/1ABB25A0  created: 2013-07-01 23:11:07 +0200 CEST  expires: 2013-07-08  usage: E
	// sub  1024R/96A672F5  created: 2013-07-01 23:11:23 +0200 CEST  expires: 2013-07-31  usage: E
	//
	// So this should select the newest, non-expired encryption key.
	key, ok := entity.EncryptionKey(time1)
	if !ok {
		t.Fatal("No encryption key found")
	}
	if id, expected := key.PublicKey.KeyIdShortString(), "CD3D39FF"; id != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time1.Format(timeFormat), id)
	}

	// Once the first encryption subkey has expired, the second should be
	// selected.
	time2, _ := time.Parse(timeFormat, "2013-07-09")
	key, _ = entity.EncryptionKey(time2)
	if id, expected := key.PublicKey.KeyIdShortString(), "CD3D39FF"; id != expected {
		t.Errorf("Expected key %s at time %s, but got key %s", expected, time2.Format(timeFormat), id)
	}

	// Once all the keys have expired, nothing should be returned.
	time3, _ := time.Parse(timeFormat, "2013-08-01")
	if key, ok := entity.EncryptionKey(time3); ok {
		t.Errorf("Expected no key at time %s, but got key %s", time3.Format(timeFormat), key.PublicKey.KeyIdShortString())
	}
}

func TestMissingCrossSignature(t *testing.T) {
	// This public key has a signing subkey, but the subkey does not
	// contain a cross-signature.
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(missingCrossSignatureKey))
	if len(keys) != 0 {
		t.Errorf("Accepted key with missing cross signature")
	}
	if err == nil {
		t.Fatal("Failed to detect error in keyring with missing cross signature")
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T. Wanted StructuralError", err)
	}
	const expectedMsg = "signing subkey is missing cross-signature"
	if !strings.Contains(string(structural), expectedMsg) {
		t.Fatalf("Unexpected error: %q. Expected it to contain %q", err, expectedMsg)
	}
}

func TestInvalidCrossSignature(t *testing.T) {
	// This public key has a signing subkey, and the subkey has an
	// embedded cross-signature. However, the cross-signature does
	// not correctly validate over the primary and subkey.
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(invalidCrossSignatureKey))
	if len(keys) != 0 {
		t.Errorf("Accepted key with invalid cross signature")
	}
	if err == nil {
		t.Fatal("Failed to detect error in keyring with an invalid cross signature")
	}
	structural, ok := err.(errors.StructuralError)
	if !ok {
		t.Fatalf("Unexpected class of error: %T. Wanted StructuralError", err)
	}
	const expectedMsg = "subkey signature invalid"
	if !strings.Contains(string(structural), expectedMsg) {
		t.Fatalf("Unexpected error: %q. Expected it to contain %q", err, expectedMsg)
	}
}

func TestGoodCrossSignature(t *testing.T) {
	// This public key has a signing subkey, and the subkey has an
	// embedded cross-signature which correctly validates over the
	// primary and subkey.
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(goodCrossSignatureKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with good cross signature, %d", len(keys))
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
}

func TestRevokedUserID(t *testing.T) {
	// This key contains 2 UIDs, one of which is revoked:
	// [ultimate] (1)  Golang Gopher <no-reply@golang.com>
	// [ revoked] (2)  Golang Gopher <revoked@golang.com>
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(revokedUserIDKey))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a revoked user id")
	}

	var identities []*Identity
	for _, identity := range keys[0].Identities {
		identities = append(identities, identity)
	}

	if numIdentities, numExpected := len(identities), 1; numIdentities != numExpected {
		t.Errorf("obtained %d identities, expected %d", numIdentities, numExpected)
	}

	if identityName, expectedName := identities[0].Name, "Golang Gopher <no-reply@golang.com>"; identityName != expectedName {
		t.Errorf("obtained identity %s expected %s", identityName, expectedName)
	}
}

func TestDummyPrivateKey(t *testing.T) {
	// This public key has a signing subkey, but has a dummy placeholder
	// instead of the real private key. It's used in scenarios where the
	// main private key is withheld and only signing is allowed (e.g. build
	// servers).
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(onlySubkeyNoPrivateKey))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with dummy private key, %d", len(keys))
	}
	if !keys[0].PrivateKey.Dummy() {
		t.Errorf("Primary private key should be marked as a dummy key")
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}

	// Test serialization of stub private key via entity.SerializePrivate().
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, PrivateKeyType, nil)
	if err != nil {
		t.Errorf("Failed top initialise armored key writer")
	}
	err = keys[0].SerializePrivateWithoutSigning(w, nil)
	if err != nil {
		t.Errorf("Failed to serialize entity")
	}
	if w.Close() != nil {
		t.Errorf("Failed to close writer for armored key")
	}

	keys, err = ReadArmoredKeyRing(bytes.NewBufferString(buf.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Errorf("Failed to accept key with dummy private key, %d", len(keys))
	}
	if !keys[0].PrivateKey.Dummy() {
		t.Errorf("Primary private key should be marked as a dummy key after serialisation")
	}
	if len(keys[0].Subkeys) != 1 {
		t.Errorf("Failed to accept good subkey, %d", len(keys[0].Subkeys))
	}
}

// TestExternallyRevokableKey attempts to load and parse a key with a third party revocation permission.
func TestExternallyRevocableKey(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(subkeyUsageHex))
	if err != nil {
		t.Fatal(err)
	}

	// The 0xA42704B92866382A key can be revoked by 0xBE3893CB843D0FE70C
	// according to this signature that appears within the key:
	// :signature packet: algo 1, keyid A42704B92866382A
	//    version 4, created 1396409682, md5len 0, sigclass 0x1f
	//    digest algo 2, begin of digest a9 84
	//    hashed subpkt 2 len 4 (sig created 2014-04-02)
	//    hashed subpkt 12 len 22 (revocation key: c=80 a=1 f=CE094AA433F7040BB2DDF0BE3893CB843D0FE70C)
	//    hashed subpkt 7 len 1 (not revocable)
	//    subpkt 16 len 8 (issuer key ID A42704B92866382A)
	//    data: [1024 bits]

	id := uint64(0xA42704B92866382A)
	keys := kring.KeysById(id)
	if len(keys) != 1 {
		t.Errorf("Expected to find key id %X, but got %d matches", id, len(keys))
	}
}

func TestKeyRevocation(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(revokedKeyHex))
	if err != nil {
		t.Fatal(err)
	}

	// revokedKeyHex contains these keys:
	// pub   1024R/9A34F7C0 2014-03-25 [revoked: 2014-03-25]
	// sub   1024R/1BA3CD60 2014-03-25 [revoked: 2014-03-25]
	ids := []uint64{0xA401D9F09A34F7C0, 0x5CD3BE0A1BA3CD60}

	for _, id := range ids {
		keys := kring.KeysById(id)
		if len(keys) != 1 {
			t.Errorf("Expected KeysById to find revoked key %X, but got %d matches", id, len(keys))
		}
		keys = kring.KeysByIdUsage(id, 0)
		if len(keys) != 0 {
			t.Errorf("Expected KeysByIdUsage to filter out revoked key %X, but got %d matches", id, len(keys))
		}
	}
}

func TestKeyWithRevokedSubKey(t *testing.T) {
	// This key contains a revoked sub key:
	//  pub   rsa1024/0x4CBD826C39074E38 2018-06-14 [SC]
	//        Key fingerprint = 3F95 169F 3FFA 7D3F 2B47  6F0C 4CBD 826C 3907 4E38
	//  uid   Golang Gopher <no-reply@golang.com>
	//  sub   rsa1024/0x945DB1AF61D85727 2018-06-14 [S] [revoked: 2018-06-14]

	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(keyWithSubKey))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a sub key")
	}

	identity := keys[0].Identities["Golang Gopher <no-reply@golang.com>"]
	// Test for an issue where Subkey Binding Signatures (RFC 4880 5.2.1) were added to the identity
	// preceding the Subkey Packet if the Subkey Packet was followed by more than one signature.
	// For example, the current key has the following layout:
	//    PUBKEY UID SELFSIG SUBKEY REV SELFSIG
	// The last SELFSIG would be added to the UID's signatures. This is wrong.
	if numSigs, numExpected := len(identity.Signatures), 1; numSigs != numExpected {
		t.Fatalf("got %d signatures, expected %d", numSigs, numExpected)
	}

	if numSubKeys, numExpected := len(keys[0].Subkeys), 1; numSubKeys != numExpected {
		t.Fatalf("got %d subkeys, expected %d", numSubKeys, numExpected)
	}

	subKey := keys[0].Subkeys[0]
	if subKey.Sig == nil {
		t.Fatalf("subkey signature is nil")
	}

}

func TestSubkeyRevocation(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(revokedSubkeyHex))
	if err != nil {
		t.Fatal(err)
	}

	// revokedSubkeyHex contains these keys:
	// pub   1024R/4EF7E4BECCDE97F0 2014-03-25
	// sub   1024R/D63636E2B96AE423 2014-03-25
	// sub   1024D/DBCE4EE19529437F 2014-03-25
	// sub   1024R/677815E371C2FD23 2014-03-25 [revoked: 2014-03-25]
	validKeys := []uint64{0x4EF7E4BECCDE97F0, 0xD63636E2B96AE423, 0xDBCE4EE19529437F}
	revokedKey := uint64(0x677815E371C2FD23)

	for _, id := range validKeys {
		keys := kring.KeysById(id)
		if len(keys) != 1 {
			t.Errorf("Expected KeysById to find key %X, but got %d matches", id, len(keys))
		}
		keys = kring.KeysByIdUsage(id, 0)
		if len(keys) != 1 {
			t.Errorf("Expected KeysByIdUsage to find key %X, but got %d matches", id, len(keys))
		}
	}

	keys := kring.KeysById(revokedKey)
	if len(keys) != 1 {
		t.Errorf("Expected KeysById to find key %X, but got %d matches", revokedKey, len(keys))
	}

	keys = kring.KeysByIdUsage(revokedKey, 0)
	if len(keys) != 0 {
		t.Errorf("Expected KeysByIdUsage to filter out revoked key %X, but got %d matches", revokedKey, len(keys))
	}
}

func TestKeyWithSubKeyAndBadSelfSigOrder(t *testing.T) {
	// This key was altered so that the self signatures following the
	// subkey are in a sub-optimal order.
	//
	// Note: Should someone have to create a similar key again, look into
	//       gpgsplit, gpg --dearmor, and gpg --enarmor.
	//
	// The packet ordering is the following:
	//    PUBKEY UID UIDSELFSIG SUBKEY SELFSIG1 SELFSIG2
	//
	// Where:
	//    SELFSIG1 expires on 2018-06-14 and was created first
	//    SELFSIG2 does not expire and was created after SELFSIG1
	//
	// Test for RFC 4880 5.2.3.3:
	// > An implementation that encounters multiple self-signatures on the
	// > same object may resolve the ambiguity in any way it sees fit, but it
	// > is RECOMMENDED that priority be given to the most recent self-
	// > signature.
	//
	// This means that we should keep SELFSIG2.

	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(keyWithSubKeyAndBadSelfSigOrder))
	if err != nil {
		t.Fatal(err)
	}

	if len(keys) != 1 {
		t.Fatal("Failed to read key with a sub key and a bad selfsig packet order")
	}

	key := keys[0]

	if numKeys, expected := len(key.Subkeys), 1; numKeys != expected {
		t.Fatalf("Read %d subkeys, expected %d", numKeys, expected)
	}

	subKey := key.Subkeys[0]

	if lifetime := subKey.Sig.KeyLifetimeSecs; lifetime != nil {
		t.Errorf("The signature has a key lifetime (%d), but it should be nil", *lifetime)
	}

}

func TestKeyUsage(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(subkeyUsageHex))
	if err != nil {
		t.Fatal(err)
	}

	// subkeyUsageHex contains these keys:
	// pub  1024R/2866382A  created: 2014-04-01  expires: never       usage: SC
	// sub  1024R/936C9153  created: 2014-04-01  expires: never       usage: E
	// sub  1024R/64D5F5BB  created: 2014-04-02  expires: never       usage: E
	// sub  1024D/BC0BA992  created: 2014-04-02  expires: never       usage: S
	certifiers := []uint64{0xA42704B92866382A}
	signers := []uint64{0xA42704B92866382A, 0x42CE2C64BC0BA992}
	encrypters := []uint64{0x09C0C7D9936C9153, 0xC104E98664D5F5BB}

	for _, id := range certifiers {
		keys := kring.KeysByIdUsage(id, packet.KeyFlagCertify)
		if len(keys) == 1 {
			if keys[0].PublicKey.KeyId != id {
				t.Errorf("Expected to find certifier key id %X, but got %X", id, keys[0].PublicKey.KeyId)
			}
		} else {
			t.Errorf("Expected one match for certifier key id %X, but got %d matches", id, len(keys))
		}
	}

	for _, id := range signers {
		keys := kring.KeysByIdUsage(id, packet.KeyFlagSign)
		if len(keys) == 1 {
			if keys[0].PublicKey.KeyId != id {
				t.Errorf("Expected to find signing key id %X, but got %X", id, keys[0].PublicKey.KeyId)
			}
		} else {
			t.Errorf("Expected one match for signing key id %X, but got %d matches", id, len(keys))
		}

		// This keyring contains no encryption keys that are also good for signing.
		keys = kring.KeysByIdUsage(id, packet.KeyFlagEncryptStorage|packet.KeyFlagEncryptCommunications)
		if len(keys) != 0 {
			t.Errorf("Unexpected match for encryption key id %X", id)
		}
	}

	for _, id := range encrypters {
		keys := kring.KeysByIdUsage(id, packet.KeyFlagEncryptStorage|packet.KeyFlagEncryptCommunications)
		if len(keys) == 1 {
			if keys[0].PublicKey.KeyId != id {
				t.Errorf("Expected to find encryption key id %X, but got %X", id, keys[0].PublicKey.KeyId)
			}
		} else {
			t.Errorf("Expected one match for encryption key id %X, but got %d matches", id, len(keys))
		}

		// This keyring contains no encryption keys that are also good for signing.
		keys = kring.KeysByIdUsage(id, packet.KeyFlagSign)
		if len(keys) != 0 {
			t.Errorf("Unexpected match for signing key id %X", id)
		}
	}
}

func TestIdVerification(t *testing.T) {
	kring, err := ReadKeyRing(readerFromHex(testKeys1And2PrivateHex))
	if err != nil {
		t.Fatal(err)
	}
	if err := kring[1].PrivateKey.Decrypt([]byte("passphrase")); err != nil {
		t.Fatal(err)
	}

	const identity = "Test Key 1 (RSA)"
	if err := kring[0].SignIdentity(identity, kring[1], nil); err != nil {
		t.Fatal(err)
	}

	ident, ok := kring[0].Identities[identity]
	if !ok {
		t.Fatal("identity missing from key after signing")
	}

	checked := false
	for _, sig := range ident.Signatures {
		if sig.IssuerKeyId == nil || *sig.IssuerKeyId != kring[1].PrimaryKey.KeyId {
			continue
		}

		if err := kring[1].PrimaryKey.VerifyUserIdSignature(identity, kring[0].PrimaryKey, sig); err != nil {
			t.Fatalf("error verifying new identity signature: %s", err)
		}
		checked = true
		break
	}

	if !checked {
		t.Fatal("didn't find identity signature in Entity")
	}
}

func TestNewEntityWithDefaultHash(t *testing.T) {
	for _, hash := range hashes {
		c := &packet.Config{
			DefaultHash: hash,
		}
		entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", c)
		if err != nil {
			t.Fatal(err)
		}

		for _, identity := range entity.Identities {
			prefs := identity.SelfSignature.PreferredHash
			if len(prefs) == 0 {
				t.Fatal("didn't find a preferred hash list in self signature")
			}
			ph := hashToHashId(c.DefaultHash)
			if prefs[0] != ph {
				t.Fatalf("Expected preferred hash to be %d, got %d", ph, prefs[0])
			}
		}
	}
}

func TestNewEntityNilConfigPreferredHash(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, identity := range entity.Identities {
		prefs := identity.SelfSignature.PreferredHash
		if len(prefs) != 1 {
			t.Fatal("expected preferred hashes list to be [SHA256]")
		}
	}
}

func TestNewEntityCorrectName(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(entity.Identities) != 1 {
		t.Fatalf("len(entity.Identities) = %d, want 1", len(entity.Identities))
	}
	var got string
	for _, i := range entity.Identities {
		got = i.Name
	}
	want := "Golang Gopher (Test Key) <no-reply@golang.com>"
	if got != want {
		t.Fatalf("Identity.Name = %q, want %q", got, want)
	}
}

func TestNewEntityWithDefaultCipher(t *testing.T) {
	for _, cipher := range ciphers {
		c := &packet.Config{
			DefaultCipher: cipher,
		}
		entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", c)
		if err != nil {
			t.Fatal(err)
		}

		for _, identity := range entity.Identities {
			prefs := identity.SelfSignature.PreferredSymmetric
			if len(prefs) == 0 {
				t.Fatal("didn't find a preferred cipher list")
			}
			if prefs[0] != uint8(c.DefaultCipher) {
				t.Fatalf("Expected preferred cipher to be %d, got %d", uint8(c.DefaultCipher), prefs[0])
			}
		}
	}
}

func TestNewEntityNilConfigPreferredSymmetric(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, identity := range entity.Identities {
		prefs := identity.SelfSignature.PreferredSymmetric
		if len(prefs) != 1 || prefs[0] != algorithm.AES128.Id() {
			t.Fatal("expected preferred ciphers list to be [AES128]")
		}
	}
}

func TestNewEntityWithDefaultAead(t *testing.T) {
	for _, aeadMode := range aeadModes {
		cfg := &packet.Config{
			AEADConfig: &packet.AEADConfig{
				DefaultMode: aeadMode,
			},
		}
		entity, err := NewEntity("Botvinnik", "1.e4", "tal@chess.com", cfg)
		if err != nil {
			t.Fatal(err)
		}

		for _, identity := range entity.Identities {
			if len(identity.SelfSignature.PreferredAEAD) == 0 {
				t.Fatal("didn't find a preferred mode in self signature")
			}
			mode := identity.SelfSignature.PreferredAEAD[0]
			if mode != uint8(cfg.AEAD().DefaultMode) {
				t.Fatalf("Expected preferred mode to be %d, got %d",
					uint8(cfg.AEAD().DefaultMode),
					identity.SelfSignature.PreferredAEAD[0])
			}
		}
	}
}

func TestNewEntityPublicSerialization(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	serializedEntity := bytes.NewBuffer(nil)
	err = entity.Serialize(serializedEntity)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewEntityPrivateSerialization(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	serializedEntity := bytes.NewBuffer(nil)
	err = entity.SerializePrivateWithoutSigning(serializedEntity, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestEntityPrivateSerialization(t *testing.T) {
	keys, err := ReadArmoredKeyRing(bytes.NewBufferString(armoredPrivateKeyBlock))
	if err != nil {
		t.Fatal(err)
	}

	for _, entity := range keys {
		serializedEntity := bytes.NewBuffer(nil)
		err = entity.SerializePrivateWithoutSigning(serializedEntity, nil)
		if err != nil {
			t.Fatal(err)
		}

		_, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAddSubkey(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	for _, sk := range entity.Subkeys {
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSubkeySerialized(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(nil)
	if err != nil {
		t.Fatal(err)
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivateWithoutSigning(serializedEntity, nil)

	entity, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	for _, sk := range entity.Subkeys {
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}
}

func TestAddSubkeyWithConfig(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm: packet.PubKeyAlgoEdDSA,
	}
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	if entity.Subkeys[1].PublicKey.PubKeyAlgo != packet.PubKeyAlgoEdDSA {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoEdDSA,
			entity.Subkeys[1].PublicKey.PubKeyAlgo)
	}

	if entity.Subkeys[2].PublicKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoECDH,
			entity.Subkeys[2].PublicKey.PubKeyAlgo)
	}

	if entity.Subkeys[1].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.Hash)
	}

	if entity.Subkeys[1].Sig.EmbeddedSignature.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.EmbeddedSignature.Hash)
	}

	if entity.Subkeys[2].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[2].Sig.Hash)
	}

	for _, sk := range entity.Subkeys {
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

	_, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
}

func TestAddSubkeyWithConfigSerialized(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
		Algorithm: packet.PubKeyAlgoEdDSA,
	}
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddSigningSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.AddEncryptionSubkey(c)
	if err != nil {
		t.Fatal(err)
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivateWithoutSigning(serializedEntity, nil)

	entity, err = ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Subkeys) != 3 {
		t.Fatalf("Expected 3 subkeys, got %d", len(entity.Subkeys))
	}

	if entity.Subkeys[1].PublicKey.PubKeyAlgo != packet.PubKeyAlgoEdDSA {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoEdDSA,
			entity.Subkeys[1].PublicKey.PubKeyAlgo)
	}

	if entity.Subkeys[2].PublicKey.PubKeyAlgo != packet.PubKeyAlgoECDH {
		t.Fatalf("Expected subkey algorithm: %v, got: %v", packet.PubKeyAlgoECDH,
			entity.Subkeys[2].PublicKey.PubKeyAlgo)
	}

	if entity.Subkeys[1].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.Hash)
	}

	if entity.Subkeys[1].Sig.EmbeddedSignature.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[1].Sig.EmbeddedSignature.Hash)
	}

	if entity.Subkeys[2].Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected subkey hash method: %v, got: %v", c.DefaultHash,
			entity.Subkeys[2].Sig.Hash)
	}

	for _, sk := range entity.Subkeys {
		err = entity.PrimaryKey.VerifyKeySignature(sk.PublicKey, sk.Sig)
		if err != nil {
			t.Errorf("Invalid subkey signature: %v", err)
		}
	}
}

func TestRevokeKey(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.RevokeKey(packet.NoReason, "Key revocation", nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Revocations) == 0 {
		t.Fatal("Revocation signature missing from entity")
	}

	for _, r := range entity.Revocations {
		err = entity.PrimaryKey.VerifyRevocationSignature(r)
		if err != nil {
			t.Errorf("Invalid revocation: %v", err)
		}
	}
}

func TestRevokeKeyWithConfig(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
	}

	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = entity.RevokeKey(packet.NoReason, "Key revocation", c)
	if err != nil {
		t.Fatal(err)
	}

	if len(entity.Revocations) == 0 {
		t.Fatal("Revocation signature missing from entity")
	}

	if entity.Revocations[0].Hash != c.DefaultHash {
		t.Fatalf("Expected signature hash method: %v, got: %v", c.DefaultHash,
			entity.Revocations[0].Hash)
	}

	for _, r := range entity.Revocations {
		err = entity.PrimaryKey.VerifyRevocationSignature(r)
		if err != nil {
			t.Errorf("Invalid revocation: %v", err)
		}
	}
}

func TestRevokeSubkey(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := &entity.Subkeys[0]
	err = entity.RevokeSubkey(sk, packet.NoReason, "Key revocation", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = sk.PublicKey.VerifySubkeyRevocationSignature(sk.Sig, entity.PrimaryKey)
	if err != nil {
		t.Fatal(err)
	}

	if entity.Subkeys[0].Sig.RevocationReason == nil {
		t.Fatal("Revocation reason was not set")
	}
	if entity.Subkeys[0].Sig.RevocationReasonText == "" {
		t.Fatal("Revocation reason text was not set")
	}

	serializedEntity := bytes.NewBuffer(nil)
	entity.SerializePrivate(serializedEntity, nil)

	// Make sure revocation reason subpackets are not lost during serialization.
	newEntity, err := ReadEntity(packet.NewReader(bytes.NewBuffer(serializedEntity.Bytes())))
	if err != nil {
		t.Fatal(err)
	}

	if newEntity.Subkeys[0].Sig.RevocationReason == nil {
		t.Fatal("Revocation reason lost after serialization of entity")
	}
	if newEntity.Subkeys[0].Sig.RevocationReasonText == "" {
		t.Fatal("Revocation reason text lost after serialization of entity")
	}
}

func TestRevokeSubkeyWithAnotherEntity(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := entity.Subkeys[0]

	newEntity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	err = newEntity.RevokeSubkey(&sk, packet.NoReason, "Key revocation", nil)
	if err == nil {
		t.Fatal("Entity was able to revoke a subkey owned by a different entity")
	}
}

func TestRevokeSubkeyWithInvalidSignature(t *testing.T) {
	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := entity.Subkeys[0]
	sk.Sig = &packet.Signature{}

	err = entity.RevokeSubkey(&sk, packet.NoReason, "Key revocation", nil)
	if err == nil {
		t.Fatal("Entity was able to revoke a subkey with invalid signature")
	}
}

func TestRevokeSubkeyWithConfig(t *testing.T) {
	c := &packet.Config{
		DefaultHash: crypto.SHA512,
	}

	entity, err := NewEntity("Golang Gopher", "Test Key", "no-reply@golang.com", nil)
	if err != nil {
		t.Fatal(err)
	}

	sk := entity.Subkeys[0]
	err = entity.RevokeSubkey(&sk, packet.NoReason, "Key revocation", c)
	if err != nil {
		t.Fatal(err)
	}

	if sk.Sig.Hash != c.DefaultHash {
		t.Fatalf("Expected signature hash method: %v, got: %v", c.DefaultHash,
			sk.Sig.Hash)
	}

	err = sk.PublicKey.VerifySubkeyRevocationSignature(sk.Sig, entity.PrimaryKey)
	if err != nil {
		t.Fatal(err)
	}
}
