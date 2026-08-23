// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.27 || fips140v1.0

package ssh

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// The ML-DSA public key sizes, from [SSH-MLDSA], Section 3, spelled out because
// crypto/mldsa is not available in this build.
var mldsaPublicKeySizes = map[string]int{
	KeyAlgoMLDSA44: 1312,
	KeyAlgoMLDSA65: 1952,
	KeyAlgoMLDSA87: 2592,
}

func TestMLDSAUnsupported(t *testing.T) {
	if len(mldsaKeyAlgos) != 0 {
		t.Errorf("mldsaKeyAlgos = %v, want empty", mldsaKeyAlgos)
	}

	supported := SupportedAlgorithms()
	insecure := InsecureAlgorithms()
	for algo := range mldsaPublicKeySizes {
		t.Run(algo, func(t *testing.T) {
			for _, tt := range []struct {
				name  string
				algos []string
			}{
				{"SupportedAlgorithms.HostKeys", supported.HostKeys},
				{"SupportedAlgorithms.PublicKeyAuths", supported.PublicKeyAuths},
				{"InsecureAlgorithms.HostKeys", insecure.HostKeys},
				{"InsecureAlgorithms.PublicKeyAuths", insecure.PublicKeyAuths},
				{"defaultHostKeyAlgos", defaultHostKeyAlgos},
				{"defaultPubKeyAuthAlgos", defaultPubKeyAuthAlgos},
			} {
				if slices.Contains(tt.algos, algo) {
					t.Errorf("%s contains %s, but this build can't use it", tt.name, algo)
				}
			}

			blob := Marshal(struct {
				Name     string
				KeyBytes []byte
			}{algo, make([]byte, mldsaPublicKeySizes[algo])})
			if _, err := ParsePublicKey(blob); !errors.Is(err, errors.ErrUnsupported) {
				t.Errorf("ParsePublicKey: got %v, want %v", err, errors.ErrUnsupported)
			}

			// Configuring the algorithm must be rejected up front, rather than
			// failing once a client tries to use it.
			c1, c2, err := netPipe()
			if err != nil {
				t.Fatalf("netPipe: %v", err)
			}
			defer c1.Close()
			defer c2.Close()
			conf := &ServerConfig{
				PublicKeyAuthAlgorithms: []string{algo},
				PublicKeyCallback: func(ConnMetadata, PublicKey) (*Permissions, error) {
					return nil, nil
				},
			}
			conf.AddHostKey(testSigners["ed25519"])
			if _, _, _, err := NewServerConn(c1, conf); err == nil ||
				!strings.Contains(err.Error(), "unsupported public key authentication algorithm") {
				t.Errorf("NewServerConn: got %v, want an unsupported algorithm error", err)
			}
		})
	}
}

func TestMLDSAUnsupportedKeyTypes(t *testing.T) {
	if _, err := NewPublicKey("not a key"); err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("NewPublicKey: %v", err)
	}
	if _, err := MarshalPrivateKey("not a key", "comment"); err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("MarshalPrivateKey: %v", err)
	}
}
