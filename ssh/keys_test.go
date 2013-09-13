package ssh

import (
	"crypto"
	"crypto/dsa"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
)

func TestRSAMarshal(t *testing.T) {
	k0 := &rsakey.PublicKey
	k1 := NewRSAPublicKey(k0)
	k2, rest, ok := ParsePublicKey(MarshalPublicKey(k1))
	if !ok {
		t.Errorf("could not parse back Blob output")
	}
	if len(rest) > 0 {
		t.Errorf("trailing junk in RSA Blob() output")
	}
	if !reflect.DeepEqual(k0, k2.RawKey().(*rsa.PublicKey)) {
		t.Errorf("got %#v in roundtrip, want %#v", k2.RawKey(), k0)
	}
}

func TestRSAKeyVerify(t *testing.T) {
	pub := NewRSAPublicKey(&rsakey.PublicKey)

	data := []byte("sign me")
	h := crypto.SHA1.New()
	h.Write(data)
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, rsakey, crypto.SHA1, digest)
	if err != nil {
		t.Fatalf("SignPKCS1v15: %v", err)
	}

	if !pub.Verify(data, sig) {
		t.Errorf("publicKey.Verify failed")
	}
}

func TestDSAMarshal(t *testing.T) {
	k0 := &dsakey.PublicKey
	k1 := NewDSAPublicKey(k0)
	k2, rest, ok := ParsePublicKey(MarshalPublicKey(k1))
	if !ok {
		t.Errorf("could not parse back Blob output")
	}
	if len(rest) > 0 {
		t.Errorf("trailing junk in DSA Blob() output")
	}
	if !reflect.DeepEqual(k0, k2.RawKey().(*dsa.PublicKey)) {
		t.Errorf("got %#v in roundtrip, want %#v", k2.RawKey(), k0)
	}
}

// TODO(hanwen): test for ECDSA marshal.
