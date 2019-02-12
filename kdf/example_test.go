package kdf

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
)

// Usage example that expands one master secret into three other
// cryptographically secure keys using KDF2.
func Example_usage() {
	// Cryptographically secure master secret.
	seed := []byte{0x00, 0x01, 0x02, 0x03} // i.e. NOT this.

	// Non-secret context info, optional (can be nil).
	other := []byte("kdf example")

	// Generate three 128-bit/16-byte derived keys.
	kdf, err := NewKDF2(seed, other, crypto.SHA256, 48)
	if err != nil {
		panic(err)
	}

	var keys [][]byte
	for i := 0; i < 3; i++ {
		key := make([]byte, 16)
		if _, err := io.ReadFull(kdf, key); err != nil {
			panic(err)
		}
		keys = append(keys, key)
	}

	for i := range keys {
		fmt.Printf("Key #%d: %v\n", i+1, !bytes.Equal(keys[i], make([]byte, 16)))
	}

	// Output:
	// Key #1: true
	// Key #2: true
	// Key #3: true
}
