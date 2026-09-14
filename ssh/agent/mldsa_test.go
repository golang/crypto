// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !fips140v1.0

package agent

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestMLDSAKeys(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	certKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewSignerFromKey(certKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := &ssh.Certificate{
		Key:             certSigner.PublicKey(),
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"testuser"},
		ValidBefore:     ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, testSigners["ed25519"]); err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	keyring := NewKeyring()
	for _, k := range []AddedKey{
		{PrivateKey: key, Comment: "key"},
		{PrivateKey: certKey, Certificate: cert, Comment: "cert"},
	} {
		if err := keyring.Add(k); err != nil {
			t.Fatalf("Keyring.Add: %v", err)
		}
	}
	agent, cleanup := startAgent(t, keyring)
	defer cleanup()

	for _, k := range []AddedKey{
		{PrivateKey: key},
		{PrivateKey: certKey, Certificate: cert},
	} {
		if err := agent.Add(k); err == nil || !strings.Contains(err.Error(), "unsupported key type") {
			t.Errorf("Add over the protocol: %v, want an unsupported key type error", err)
		}
	}

	keys, err := agent.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 || keys[0].Type() != ssh.KeyAlgoMLDSA65 || keys[1].Type() != ssh.CertAlgoMLDSA65v01Go {
		t.Fatalf("List returned %v", keys)
	}
	data := []byte("sign me")
	for _, k := range keys {
		sig, err := agent.Sign(k, data)
		if err != nil {
			t.Fatalf("Sign(%s): %v", k.Type(), err)
		}
		pub, err := ssh.ParsePublicKey(k.Marshal())
		if err != nil {
			t.Fatal(err)
		}
		if err := pub.Verify(data, sig); err != nil {
			t.Errorf("Verify(%s): %v", k.Type(), err)
		}
	}

	// The certificate signer must sign with the underlying algorithm, which
	// is what the client asks for during public key authentication.
	signers, err := agent.Signers()
	if err != nil {
		t.Fatalf("Signers: %v", err)
	}
	as := signers[1].(ssh.AlgorithmSigner)
	if _, err := as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoMLDSA65); err != nil {
		t.Errorf("SignWithAlgorithm(%s): %v", ssh.KeyAlgoMLDSA65, err)
	}
	if _, err := as.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoMLDSA44); err == nil {
		t.Errorf("SignWithAlgorithm(%s) accepted the wrong algorithm", ssh.KeyAlgoMLDSA44)
	}

	checker := &ssh.CertChecker{IsUserAuthority: func(k ssh.PublicKey) bool {
		return bytes.Equal(k.Marshal(), testPublicKeys["ed25519"].Marshal())
	}}
	for _, tt := range []struct {
		name   string
		signer ssh.Signer
		accept func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error)
	}{
		{"key", signers[0], func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(k.Marshal(), keys[0].Marshal()) {
				return nil, errors.New("pubkey rejected")
			}
			return nil, nil
		}},
		{"cert", signers[1], checker.Authenticate},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a, b, err := netPipe()
			if err != nil {
				t.Fatalf("netPipe: %v", err)
			}
			defer a.Close()
			defer b.Close()

			serverConf := &ssh.ServerConfig{
				PublicKeyAuthAlgorithms: []string{ssh.KeyAlgoMLDSA65},
				PublicKeyCallback:       tt.accept,
			}
			serverConf.AddHostKey(testSigners["ed25519"])
			serverErr := make(chan error, 1)
			go func() {
				_, _, _, err := ssh.NewServerConn(a, serverConf)
				serverErr <- err
			}()

			conn, _, _, err := ssh.NewClientConn(b, "", &ssh.ClientConfig{
				User:            "testuser",
				Auth:            []ssh.AuthMethod{ssh.PublicKeys(tt.signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			})
			if err != nil {
				t.Fatalf("NewClientConn: %v (server: %v)", err, <-serverErr)
			}
			defer conn.Close()
			if err := <-serverErr; err != nil {
				t.Errorf("NewServerConn: %v", err)
			}
		})
	}
}
