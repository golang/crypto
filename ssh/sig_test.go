package ssh

import (
	"crypto/rand"
	"encoding/pem"
	"testing"
)

func TestEd25519SignVerify(t *testing.T) {
	signer, ok := testSigners["ed25519"]
	if !ok {
		t.Fatalf("cannot find signer: ed25519")
	}

	const message = "gopher test message"
	const namespace = "gopher@test"

	signature, err := Sign(signer, rand.Reader, []byte(message), namespace)
	if err != nil {
		t.Fatalf("could not sign: %v", err)
	}

	block, _ := pem.Decode(signature)
	err = Verify(signer.PublicKey(), []byte(message), block.Bytes, namespace)
	if err != nil {
		t.Fatalf("could not verify signature: %v", err)
	}
}
