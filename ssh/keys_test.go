package ssh

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"strings"
	"testing"
)

var ecdsaKey Signer

func rawKey(pub PublicKey) interface{} {
	switch k := pub.(type) {
	case *rsaPublicKey:
		return (*rsa.PublicKey)(k)
	case *dsaPublicKey:
		return (*dsa.PublicKey)(k)
	case *ecdsaPublicKey:
		return (*ecdsa.PublicKey)(k)
	}
	panic("unknown key type")
}

func TestKeyMarshalParse(t *testing.T) {
	keys := []Signer{rsaKey, dsaKey, ecdsaKey}
	for _, priv := range keys {
		pub := priv.PublicKey()
		roundtrip, rest, ok := ParsePublicKey(MarshalPublicKey(pub))
		if !ok {
			t.Errorf("ParsePublicKey(%T) failed", pub)
		}

		if len(rest) > 0 {
			t.Errorf("ParsePublicKey(%T): trailing junk", pub)
		}

		k1 := rawKey(pub)
		k2 := rawKey(roundtrip)

		if !reflect.DeepEqual(k1, k2) {
			t.Errorf("got %#v in roundtrip, want %#v", k2, k1)
		}
	}
}

func TestUnsupportedCurves(t *testing.T) {
	raw, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	if _, err = NewSignerFromKey(raw); err == nil || !strings.Contains(err.Error(), "only P256") {
		t.Fatalf("NewPrivateKey should not succeed with P224, got: %v", err)
	}

	if _, err = NewPublicKey(&raw.PublicKey); err == nil || !strings.Contains(err.Error(), "only P256") {
		t.Fatalf("NewPublicKey should not succeed with P224, got: %v", err)
	}
}

func TestNewPublicKey(t *testing.T) {
	keys := []Signer{rsaKey, dsaKey, ecdsaKey}
	for _, k := range keys {
		raw := rawKey(k.PublicKey())
		pub, err := NewPublicKey(raw)
		if err != nil {
			t.Errorf("NewPublicKey(%#v): %v", raw, err)
		}
		if !reflect.DeepEqual(k.PublicKey(), pub) {
			t.Errorf("NewPublicKey(%#v) = %#v, want %#v", raw, pub, k.PublicKey())
		}
	}
}

func TestKeySignVerify(t *testing.T) {
	keys := []Signer{rsaKey, dsaKey, ecdsaKey}
	for _, priv := range keys {
		pub := priv.PublicKey()

		data := []byte("sign me")
		sig, err := priv.Sign(rand.Reader, data)
		if err != nil {
			t.Fatalf("Sign(%T): %v", priv, err)
		}

		if !pub.Verify(data, sig) {
			t.Errorf("publicKey.Verify(%T) failed", priv)
		}
	}
}

func TestParseRSAPrivateKey(t *testing.T) {
	key, err := ParsePrivateKey([]byte(testServerPrivateKey))
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	rsa, ok := key.(*rsaPrivateKey)
	if !ok {
		t.Fatalf("got %T, want *rsa.PrivateKey", rsa)
	}

	if err := rsa.Validate(); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

func TestParseECPrivateKey(t *testing.T) {
	// Taken from the data in test/ .
	pem := []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINGWx0zo6fhJ/0EAfrPzVFyFC9s18lBt3cRoEDhS3ARooAoGCCqGSM49
AwEHoUQDQgAEi9Hdw6KvZcWxfg2IDhA7UkpDtzzt6ZqJXSsFdLd+Kx4S3Sx4cVO+
6/ZOXRnPmNAlLUqjShUsUBBngG0u2fqEqA==
-----END EC PRIVATE KEY-----`)

	key, err := ParsePrivateKey(pem)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}

	ecKey, ok := key.(*ecdsaPrivateKey)
	if !ok {
		t.Fatalf("got %T, want *ecdsaPrivateKey", ecKey)
	}

	if !validateECPublicKey(ecKey.Curve, ecKey.X, ecKey.Y) {
		t.Fatalf("public key does not validate.")
	}
}

func init() {
	raw, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaKey, _ = NewSignerFromKey(raw)
}
