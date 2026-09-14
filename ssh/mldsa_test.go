// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !fips140v1.0

package ssh

import (
	"bytes"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
)

var mldsaAlgorithms = []string{KeyAlgoMLDSA44, KeyAlgoMLDSA65, KeyAlgoMLDSA87}

func mldsaTestKey(t *testing.T, algo string) *mldsa.PrivateKey {
	t.Helper()
	params, err := mldsaParameters(algo)
	if err != nil {
		t.Fatalf("mldsaParameters(%q): %v", algo, err)
	}
	key, err := mldsa.GenerateKey(params)
	if err != nil {
		t.Fatalf("GenerateKey(%s): %v", params, err)
	}
	return key
}

func mldsaTestSigner(t *testing.T, algo string) Signer {
	t.Helper()
	signer, err := NewSignerFromKey(mldsaTestKey(t, algo))
	if err != nil {
		t.Fatalf("NewSignerFromKey(%s): %v", algo, err)
	}
	return signer
}

func TestMLDSAPublicKeyRoundTrip(t *testing.T) {
	for _, algo := range mldsaAlgorithms {
		t.Run(algo, func(t *testing.T) {
			params, err := mldsaParameters(algo)
			if err != nil {
				t.Fatal(err)
			}
			signer := mldsaTestSigner(t, algo)
			pub := signer.PublicKey()
			if pub.Type() != algo {
				t.Errorf("Type() = %q, want %q", pub.Type(), algo)
			}

			blob := pub.Marshal()
			// string algo || string key, as per [SSH-MLDSA], Section 4.
			if want := 4 + len(algo) + 4 + params.PublicKeySize(); len(blob) != want {
				t.Errorf("marshaled key is %d bytes, want %d", len(blob), want)
			}

			parsed, err := ParsePublicKey(blob)
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			if parsed.Type() != algo {
				t.Errorf("parsed Type() = %q, want %q", parsed.Type(), algo)
			}
			if !bytes.Equal(parsed.Marshal(), blob) {
				t.Error("marshaled parsed key differs from the original")
			}

			authorized := MarshalAuthorizedKey(pub)
			parsed, _, _, _, err = ParseAuthorizedKey(authorized)
			if err != nil {
				t.Fatalf("ParseAuthorizedKey: %v", err)
			}
			if !bytes.Equal(parsed.Marshal(), blob) {
				t.Error("authorized_keys round trip changed the key")
			}

			cryptoPub, ok := pub.(CryptoPublicKey)
			if !ok {
				t.Fatal("public key doesn't implement CryptoPublicKey")
			}
			mldsaPub, ok := cryptoPub.CryptoPublicKey().(*mldsa.PublicKey)
			if !ok {
				t.Fatalf("CryptoPublicKey returned %T, want *mldsa.PublicKey", cryptoPub.CryptoPublicKey())
			}
			// A crypto/mldsa key must round trip back to the same ssh.PublicKey.
			sshPub, err := NewPublicKey(mldsaPub)
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}
			if !bytes.Equal(sshPub.Marshal(), blob) {
				t.Error("NewPublicKey round trip changed the key")
			}

			if algos := signer.(MultiAlgorithmSigner).Algorithms(); !slices.Equal(algos, []string{algo}) {
				t.Errorf("Algorithms() = %v, want [%s]", algos, algo)
			}
		})
	}
}

func TestMLDSASignAndVerify(t *testing.T) {
	for _, algo := range mldsaAlgorithms {
		t.Run(algo, func(t *testing.T) {
			params, err := mldsaParameters(algo)
			if err != nil {
				t.Fatal(err)
			}
			signer := mldsaTestSigner(t, algo)
			data := []byte("sign me")

			sig, err := signer.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if sig.Format != algo {
				t.Errorf("signature format = %q, want %q", sig.Format, algo)
			}
			if len(sig.Blob) != params.SignatureSize() {
				t.Errorf("signature is %d bytes, want %d", len(sig.Blob), params.SignatureSize())
			}
			if err := signer.PublicKey().Verify(data, sig); err != nil {
				t.Errorf("Verify: %v", err)
			}

			// The wire format must be verifiable after a full round trip.
			pub, err := ParsePublicKey(signer.PublicKey().Marshal())
			if err != nil {
				t.Fatal(err)
			}
			if err := pub.Verify(data, sig); err != nil {
				t.Errorf("Verify after round trip: %v", err)
			}
		})
	}
}

func TestMLDSAVerifyRejectsBadSignatures(t *testing.T) {
	const algo = KeyAlgoMLDSA65
	signer := mldsaTestSigner(t, algo)
	pub := signer.PublicKey()
	data := []byte("sign me")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	shortSig := slices.Clone(sig.Blob)[:len(sig.Blob)-1]
	longSig := append(slices.Clone(sig.Blob), 0)

	// A valid ML-DSA-44 signature must not be accepted by an ML-DSA-65 key.
	smallerSig, err := mldsaTestSigner(t, KeyAlgoMLDSA44).Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	for _, tt := range []struct {
		name    string
		sig     *Signature
		wantErr string
	}{
		{"wrong format", &Signature{Format: KeyAlgoED25519, Blob: sig.Blob}, "signature type"},
		{"other parameter set format", &Signature{Format: KeyAlgoMLDSA44, Blob: sig.Blob}, "signature type"},
		{"signature from another parameter set", smallerSig, "signature type"},
		{"truncated signature", &Signature{Format: algo, Blob: shortSig}, "did not verify"},
		{"extended signature", &Signature{Format: algo, Blob: longSig}, "did not verify"},
		{"empty signature", &Signature{Format: algo, Blob: nil}, "did not verify"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := pub.Verify(data, tt.sig)
			if err == nil {
				t.Fatal("Verify accepted an invalid signature")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Verify: %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestMLDSAParsePublicKeyRejectsInvalid(t *testing.T) {
	const algo = KeyAlgoMLDSA65
	params, err := mldsaParameters(algo)
	if err != nil {
		t.Fatal(err)
	}
	key := mldsaTestKey(t, algo)
	pub := key.PublicKey().Bytes()

	marshal := func(algo string, key []byte) []byte {
		return Marshal(struct {
			Name     string
			KeyBytes []byte
		}{algo, key})
	}

	for _, tt := range []struct {
		name    string
		blob    []byte
		wantErr string
	}{
		{"truncated key", marshal(algo, pub[:len(pub)-1]), "invalid ML-DSA"},
		{"extended key", marshal(algo, append(slices.Clone(pub), 0)), "invalid ML-DSA"},
		{"empty key", marshal(algo, nil), "invalid ML-DSA"},
		{"key of another parameter set", marshal(KeyAlgoMLDSA87, pub), "invalid ML-DSA"},
		{"trailing junk", append(marshal(algo, pub), 'x'), "trailing junk"},
		{"truncated blob", marshal(algo, pub)[:len(marshal(algo, pub))-1], ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePublicKey(tt.blob)
			if err == nil {
				t.Fatal("ParsePublicKey accepted an invalid key")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("ParsePublicKey: %v, want an error containing %q", err, tt.wantErr)
			}
		})
	}

	// A well-formed key must parse, to be sure the cases above fail for the
	// right reason.
	if _, err := ParsePublicKey(marshal(algo, pub)); err != nil {
		t.Errorf("ParsePublicKey rejected a valid %s key: %v", params, err)
	}
}

func TestMLDSAClientServer(t *testing.T) {
	for _, algo := range []string{KeyAlgoMLDSA65} {
		t.Run(algo, func(t *testing.T) {
			hostSigner := mldsaTestSigner(t, algo)
			clientSigner := mldsaTestSigner(t, algo)

			c1, c2, err := netPipe()
			if err != nil {
				t.Fatalf("netPipe: %v", err)
			}
			defer c1.Close()
			defer c2.Close()

			serverConf := &ServerConfig{
				PublicKeyAuthAlgorithms: []string{algo},
				PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
					if key.Type() != algo {
						return nil, errors.New("unexpected key type")
					}
					if !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
						return nil, errors.New("unknown public key")
					}
					return nil, nil
				},
			}
			serverConf.AddHostKey(hostSigner)
			serverErr := make(chan error, 1)
			go func() {
				_, _, _, err := NewServerConn(c1, serverConf)
				serverErr <- err
			}()

			clientConf := &ClientConfig{
				User:              "testuser",
				Auth:              []AuthMethod{PublicKeys(clientSigner)},
				HostKeyAlgorithms: []string{algo},
				HostKeyCallback:   FixedHostKey(hostSigner.PublicKey()),
			}
			conn, _, _, err := NewClientConn(c2, "", clientConf)
			if err != nil {
				t.Fatalf("client handshake: %v (server: %v)", err, <-serverErr)
			}
			defer conn.Close()
			if err := <-serverErr; err != nil {
				t.Errorf("server handshake: %v", err)
			}
		})
	}
}

func TestMLDSAInvalidKeyValues(t *testing.T) {
	for _, tt := range []struct {
		name string
		fn   func() error
	}{
		{"NewPublicKey zero", func() error {
			_, err := NewPublicKey(&mldsa.PublicKey{})
			return err
		}},
		{"NewPublicKey nil", func() error {
			_, err := NewPublicKey((*mldsa.PublicKey)(nil))
			return err
		}},
		{"NewSignerFromKey zero", func() error {
			_, err := NewSignerFromKey(&mldsa.PrivateKey{})
			return err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning an error: %v", r)
				}
			}()
			if err := tt.fn(); err == nil {
				t.Error("accepted an invalid ML-DSA key")
			}
		})
	}

	// Keys of other types must still get the generic error, not an ML-DSA one.
	if _, err := NewPublicKey("not a key"); err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("NewPublicKey of an unsupported type: %v", err)
	}
	if _, err := MarshalPrivateKey("not a key", "comment"); err == nil || !strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("MarshalPrivateKey of an unsupported type: %v", err)
	}
	if _, err := MarshalPrivateKey(mldsaTestKey(t, KeyAlgoMLDSA65), "comment"); err == nil ||
		!strings.Contains(err.Error(), "unsupported key type") {
		t.Errorf("MarshalPrivateKey of an ML-DSA key: %v", err)
	}
}

func TestMLDSADefault(t *testing.T) {
	// The ML-DSA algorithms are negotiated without any configuration on either
	// side, but come last, so that adding an ML-DSA host key to a server
	// doesn't change the key its clients already know.
	for _, tt := range []struct {
		name  string
		algos []string
		want  []string
	}{
		{"supportedHostKeyAlgos", supportedHostKeyAlgos, slices.Concat(mldsaCertAlgos, mldsaKeyAlgos)},
		{"defaultHostKeyAlgos", defaultHostKeyAlgos, slices.Concat(mldsaCertAlgos, mldsaKeyAlgos)},
		{"supportedPubKeyAuthAlgos", supportedPubKeyAuthAlgos, mldsaKeyAlgos},
		{"defaultPubKeyAuthAlgos", defaultPubKeyAuthAlgos, mldsaKeyAlgos},
	} {
		if tail := tt.algos[len(tt.algos)-len(tt.want):]; !slices.Equal(tail, tt.want) {
			t.Errorf("%s ends with %v, want %v", tt.name, tail, tt.want)
		}
	}

	t.Run("host key", func(t *testing.T) {
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatalf("netPipe: %v", err)
		}
		defer c1.Close()
		defer c2.Close()

		hostSigner := mldsaTestSigner(t, KeyAlgoMLDSA65)
		serverConf := &ServerConfig{NoClientAuth: true}
		serverConf.AddHostKey(hostSigner)
		go NewServerConn(c1, serverConf)

		var hostKey PublicKey
		conn, _, _, err := NewClientConn(c2, "", &ClientConfig{
			User: "testuser",
			HostKeyCallback: func(_ string, _ net.Addr, key PublicKey) error {
				hostKey = key
				return nil
			},
		})
		if err != nil {
			t.Fatalf("client handshake: %v", err)
		}
		defer conn.Close()
		if hostKey.Type() != KeyAlgoMLDSA65 {
			t.Errorf("negotiated host key type %q, want %q", hostKey.Type(), KeyAlgoMLDSA65)
		}
	})

	t.Run("public key auth", func(t *testing.T) {
		c1, c2, err := netPipe()
		if err != nil {
			t.Fatalf("netPipe: %v", err)
		}
		defer c1.Close()
		defer c2.Close()

		clientSigner := mldsaTestSigner(t, KeyAlgoMLDSA65)
		serverConf := &ServerConfig{
			PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
				if key.Type() != KeyAlgoMLDSA65 {
					return nil, errors.New("unexpected key type")
				}
				return nil, nil
			},
		}
		serverConf.AddHostKey(testSigners["ed25519"])
		serverErr := make(chan error, 1)
		go func() {
			_, _, _, err := NewServerConn(c1, serverConf)
			serverErr <- err
		}()

		conn, _, _, err := NewClientConn(c2, "", &ClientConfig{
			User:            "testuser",
			Auth:            []AuthMethod{PublicKeys(clientSigner)},
			HostKeyCallback: InsecureIgnoreHostKey(),
		})
		if err != nil {
			t.Fatalf("client handshake: %v (server: %v)", err, <-serverErr)
		}
		defer conn.Close()
		if err := <-serverErr; err != nil {
			t.Errorf("server handshake: %v", err)
		}
	})
}
func TestMLDSACertificateAuthority(t *testing.T) {
	authority := mldsaTestSigner(t, KeyAlgoMLDSA65)
	subject, err := NewSignerFromKey(testPrivateKeys["ed25519"])
	if err != nil {
		t.Fatal(err)
	}

	cert := &Certificate{
		Key:             subject.PublicKey(),
		CertType:        UserCert,
		KeyId:           "testuser",
		ValidPrincipals: []string{"testuser"},
		ValidBefore:     CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, authority); err != nil {
		t.Fatalf("SignCert with an ML-DSA authority: %v", err)
	}
	if cert.Signature.Format != KeyAlgoMLDSA65 {
		t.Errorf("certificate signature format = %q, want %q", cert.Signature.Format, KeyAlgoMLDSA65)
	}

	checker := &CertChecker{IsUserAuthority: func(k PublicKey) bool {
		return bytes.Equal(k.Marshal(), authority.PublicKey().Marshal())
	}}
	if err := checker.CheckCert("testuser", cert); err != nil {
		t.Errorf("CheckCert: %v", err)
	}

	// The signature must not verify once the authority's key is tampered with,
	// so that the check above can't pass vacuously.
	cert.Signature.Blob[0] ^= 0x01
	if err := checker.CheckCert("testuser", cert); err == nil {
		t.Error("CheckCert accepted a certificate with a corrupted signature")
	}
}

// The ML-DSA-65 test key of PKIX-SSH, generated with OpenSSL, and its
// fingerprint as printed by its ssh-keygen.
const (
	pkixsshMLDSA65PublicKey   = "ssh-mldsa-65 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"
	pkixsshMLDSA65Fingerprint = "SHA256:c3jQNlq1/hwElvQy4QnJom72rW3rRoUSU97F0d2tvyw"
)

func TestMLDSAPKIXSSHPublicKey(t *testing.T) {
	pub, _, _, _, err := ParseAuthorizedKey([]byte(pkixsshMLDSA65PublicKey))
	if err != nil {
		t.Fatalf("ParseAuthorizedKey: %v", err)
	}
	if pub.Type() != KeyAlgoMLDSA65 {
		t.Errorf("Type() = %q, want %q", pub.Type(), KeyAlgoMLDSA65)
	}
	if got := string(MarshalAuthorizedKey(pub)); got != pkixsshMLDSA65PublicKey+"\n" {
		t.Error("MarshalAuthorizedKey differs from the original")
	}
	if got := FingerprintSHA256(pub); got != pkixsshMLDSA65Fingerprint {
		t.Errorf("FingerprintSHA256 = %q, want %q", got, pkixsshMLDSA65Fingerprint)
	}
}

func TestMLDSAPKCS8PrivateKey(t *testing.T) {
	for _, algo := range mldsaAlgorithms {
		t.Run(algo, func(t *testing.T) {
			key := mldsaTestKey(t, algo)
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
			}
			pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

			raw, err := ParseRawPrivateKey(pemBytes)
			if err != nil {
				t.Fatalf("ParseRawPrivateKey: %v", err)
			}
			parsed, ok := raw.(*mldsa.PrivateKey)
			if !ok {
				t.Fatalf("ParseRawPrivateKey returned %T, want *mldsa.PrivateKey", raw)
			}
			if !parsed.Equal(key) {
				t.Error("parsed private key differs from the original")
			}

			signer, err := ParsePrivateKey(pemBytes)
			if err != nil {
				t.Fatalf("ParsePrivateKey: %v", err)
			}
			if signer.PublicKey().Type() != algo {
				t.Errorf("signer key type = %q, want %q", signer.PublicKey().Type(), algo)
			}
			data := []byte("sign me")
			sig, err := signer.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			pub, err := NewPublicKey(key.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if err := pub.Verify(data, sig); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestMLDSACertificate(t *testing.T) {
	authority, err := NewSignerFromKey(testPrivateKeys["ed25519"])
	if err != nil {
		t.Fatal(err)
	}
	for _, algo := range mldsaAlgorithms {
		t.Run(algo, func(t *testing.T) {
			certAlgo, ok := certificateAlgo(algo)
			if !ok {
				t.Fatalf("no certificate algorithm for %s", algo)
			}
			if !slices.Contains(mldsaCertAlgos, certAlgo) {
				t.Errorf("%s is not in mldsaCertAlgos", certAlgo)
			}
			if supported := SupportedAlgorithms(); !slices.Contains(supported.HostKeys, certAlgo) ||
				slices.Contains(supported.PublicKeyAuths, certAlgo) {
				t.Errorf("%s misplaced in SupportedAlgorithms", certAlgo)
			}
			subject := mldsaTestSigner(t, algo)
			cert := &Certificate{
				Key:             subject.PublicKey(),
				CertType:        UserCert,
				KeyId:           "testuser",
				ValidPrincipals: []string{"testuser"},
				ValidBefore:     CertTimeInfinity,
			}
			if err := cert.SignCert(rand.Reader, authority); err != nil {
				t.Fatalf("SignCert: %v", err)
			}
			if cert.Type() != certAlgo {
				t.Errorf("Type() = %q, want %q", cert.Type(), certAlgo)
			}

			// The public key fields must be the plain key blob without its
			// name: string name, string nonce, string key, uint64 serial.
			blob := cert.Marshal()
			name, rest, _ := parseString(blob)
			_, rest, _ = parseString(rest)
			keyBytes, rest, ok := parseString(rest)
			if !ok {
				t.Fatal("malformed certificate")
			}
			_, plain, _ := parseString(subject.PublicKey().Marshal())
			wantKey, _, _ := parseString(plain)
			if string(name) != certAlgo || !bytes.Equal(keyBytes, wantKey) {
				t.Error("unexpected certificate public key fields")
			}
			if len(rest) < 8 || binary.BigEndian.Uint64(rest) != cert.Serial {
				t.Error("serial number doesn't follow the public key")
			}

			parsed, err := ParsePublicKey(blob)
			if err != nil {
				t.Fatalf("ParsePublicKey: %v", err)
			}
			parsedCert, ok := parsed.(*Certificate)
			if !ok {
				t.Fatalf("ParsePublicKey returned %T, want *Certificate", parsed)
			}
			if parsedCert.Key.Type() != algo || !bytes.Equal(parsedCert.Marshal(), blob) {
				t.Error("certificate round trip changed the certificate")
			}
			authorized := MarshalAuthorizedKey(cert)
			if parsed, _, _, _, err = ParseAuthorizedKey(authorized); err != nil {
				t.Fatalf("ParseAuthorizedKey: %v", err)
			}
			if !bytes.Equal(parsed.Marshal(), blob) {
				t.Error("authorized_keys round trip changed the certificate")
			}

			checker := &CertChecker{IsUserAuthority: func(k PublicKey) bool {
				return bytes.Equal(k.Marshal(), authority.PublicKey().Marshal())
			}}
			if err := checker.CheckCert("testuser", parsedCert); err != nil {
				t.Errorf("CheckCert: %v", err)
			}

			certSigner, err := NewCertSigner(cert, subject)
			if err != nil {
				t.Fatalf("NewCertSigner: %v", err)
			}
			if certSigner.PublicKey().Type() != certAlgo {
				t.Errorf("cert signer type = %q, want %q", certSigner.PublicKey().Type(), certAlgo)
			}
			data := []byte("sign me")
			sig, err := certSigner.Sign(rand.Reader, data)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if sig.Format != algo {
				t.Errorf("signature format = %q, want %q", sig.Format, algo)
			}
			if err := parsedCert.Verify(data, sig); err != nil {
				t.Errorf("Verify: %v", err)
			}
		})
	}
}

func TestMLDSACertificateClientServer(t *testing.T) {
	const algo, certAlgo = KeyAlgoMLDSA65, CertAlgoMLDSA65v01Go
	authority := mldsaTestSigner(t, algo)
	isAuthority := func(k PublicKey) bool {
		return bytes.Equal(k.Marshal(), authority.PublicKey().Marshal())
	}

	certSigner := func(certType uint32, principal string) Signer {
		key := mldsaTestSigner(t, algo)
		cert := &Certificate{
			Key:             key.PublicKey(),
			CertType:        certType,
			ValidPrincipals: []string{principal},
			ValidBefore:     CertTimeInfinity,
		}
		if err := cert.SignCert(rand.Reader, authority); err != nil {
			t.Fatalf("SignCert: %v", err)
		}
		signer, err := NewCertSigner(cert, key)
		if err != nil {
			t.Fatalf("NewCertSigner: %v", err)
		}
		return signer
	}
	hostSigner := certSigner(HostCert, "hostname")
	userSigner := certSigner(UserCert, "testuser")

	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	checker := &CertChecker{
		IsUserAuthority: isAuthority,
		IsHostAuthority: func(k PublicKey, addr string) bool { return isAuthority(k) },
	}
	serverConf := &ServerConfig{
		PublicKeyAuthAlgorithms: []string{algo},
		PublicKeyCallback:       checker.Authenticate,
	}
	serverConf.AddHostKey(hostSigner)
	serverErr := make(chan error, 1)
	go func() {
		_, _, _, err := NewServerConn(c1, serverConf)
		serverErr <- err
	}()

	clientConf := &ClientConfig{
		User:              "testuser",
		Auth:              []AuthMethod{PublicKeys(userSigner)},
		HostKeyAlgorithms: []string{certAlgo},
		HostKeyCallback:   checker.CheckHostKey,
	}
	conn, _, _, err := NewClientConn(c2, "hostname:22", clientConf)
	if err != nil {
		t.Fatalf("client handshake: %v (server: %v)", err, <-serverErr)
	}
	defer conn.Close()
	if err := <-serverErr; err != nil {
		t.Errorf("server handshake: %v", err)
	}
}
