// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package autocert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"html/template"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme/internal/acme"
	"golang.org/x/net/context"
)

var discoTmpl = template.Must(template.New("disco").Parse(`{
	"new-reg": "{{.}}/new-reg",
	"new-authz": "{{.}}/new-authz",
	"new-cert": "{{.}}/new-cert"
}`))

var authzTmpl = template.Must(template.New("authz").Parse(`{
	"status": "pending",
	"challenges": [
		{
			"uri": "{{.}}/challenge/1",
			"type": "tls-sni-01",
			"token": "token-01"
		},
		{
			"uri": "{{.}}/challenge/2",
			"type": "tls-sni-02",
			"token": "token-02"
		}
	]
}`))

func dummyCert(san ...string) ([]byte, error) {
	// use EC key to run faster on 386
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	t := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageKeyEncipherment,
		DNSNames:              san,
	}
	return x509.CreateCertificate(rand.Reader, t, t, &key.PublicKey, key)
}

func TestGetCertificate(t *testing.T) {
	const domain = "example.org"
	man := &Manager{Prompt: AcceptTOS}

	// echo token-02 | shasum -a 256
	// then divide result in 2 parts separated by dot
	tokenCertName := "4e8eb87631187e9ff2153b56b13a4dec.13a35d002e485d60ff37354b32f665d9.token.acme.invalid"
	verifyTokenCert := func() {
		hello := &tls.ClientHelloInfo{ServerName: tokenCertName}
		_, err := man.GetCertificate(hello)
		if err != nil {
			t.Errorf("verifyTokenCert: GetCertificate(%q): %v", tokenCertName, err)
			return
		}
	}

	// ACME CA server stub
	var ca *httptest.Server
	ca = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("replay-nonce", "nonce")
		switch r.URL.Path {
		// discovery
		case "/":
			if err := discoTmpl.Execute(w, ca.URL); err != nil {
				t.Fatalf("discoTmpl: %v", err)
			}
		// client key registration
		case "/new-reg":
			w.Write([]byte("{}"))
		// domain authorization
		case "/new-authz":
			w.Header().Set("location", ca.URL+"/authz/1")
			w.WriteHeader(http.StatusCreated)
			if err := authzTmpl.Execute(w, ca.URL); err != nil {
				t.Fatalf("authzTmpl: %v", err)
			}
		// accept tls-sni-02 challenge
		case "/challenge/2":
			verifyTokenCert()
			w.Write([]byte("{}"))
		// authorization status
		case "/authz/1":
			w.Write([]byte(`{"status": "valid"}`))
		// cert request
		case "/new-cert":
			der, err := dummyCert(domain)
			if err != nil {
				t.Fatalf("new-cert: dummyCert: %v", err)
			}
			chainUp := fmt.Sprintf("<%s/ca-cert>; rel=up", ca.URL)
			w.Header().Set("link", chainUp)
			w.WriteHeader(http.StatusCreated)
			w.Write(der)
		// CA chain cert
		case "/ca-cert":
			der, err := dummyCert("ca")
			if err != nil {
				t.Fatalf("ca-cert: dummyCert: %v", err)
			}
			w.Write(der)
		default:
			t.Errorf("unrecognized r.URL.Path: %s", r.URL.Path)
		}
	}))
	defer ca.Close()

	// use EC key to run faster on 386
	key, kerr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if kerr != nil {
		t.Fatal(kerr)
	}
	man.Client = &acme.Client{
		Key:          key,
		DirectoryURL: ca.URL,
	}

	// simulate tls.Config.GetCertificate
	var (
		tlscert *tls.Certificate
		err     error
		done    = make(chan struct{})
	)
	go func() {
		hello := &tls.ClientHelloInfo{ServerName: domain}
		tlscert, err = man.GetCertificate(hello)
		close(done)
	}()
	select {
	case <-time.After(time.Minute):
		t.Fatal("man.GetCertificate took too long to return")
	case <-done:
	}
	if err != nil {
		t.Fatalf("man.GetCertificate: %v", err)
	}

	// verify the tlscert is the same we responded with from the CA stub
	if len(tlscert.Certificate) == 0 {
		t.Fatal("len(tlscert.Certificate) is 0")
	}
	cert, err := x509.ParseCertificate(tlscert.Certificate[0])
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	if len(cert.DNSNames) == 0 || cert.DNSNames[0] != domain {
		t.Errorf("cert.DNSNames = %v; want %q", cert.DNSNames, domain)
	}

	// make sure token cert was removed
	done = make(chan struct{})
	go func() {
		for {
			hello := &tls.ClientHelloInfo{ServerName: tokenCertName}
			if _, err := man.GetCertificate(hello); err != nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		close(done)
	}()
	select {
	case <-time.After(5 * time.Second):
		t.Error("token cert was not removed")
	case <-done:
	}
}

type memCache map[string][]byte

func (m memCache) Get(ctx context.Context, key string) ([]byte, error) {
	v, ok := m[key]
	if !ok {
		return nil, ErrCacheMiss
	}
	return v, nil
}

func (m memCache) Put(ctx context.Context, key string, data []byte) error {
	m[key] = data
	return nil
}

func (m memCache) Delete(ctx context.Context, key string) error {
	delete(m, key)
	return nil
}

func TestCache(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.org"},
		NotAfter:     time.Now().Add(time.Hour),
	}
	pub, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatal(err)
	}
	tlscert := &tls.Certificate{
		Certificate: [][]byte{pub},
		PrivateKey:  privKey,
	}

	cache := make(memCache)
	man := Manager{Cache: cache}
	if err := man.cachePut("example.org", tlscert); err != nil {
		t.Fatalf("man.cachePut: %v", err)
	}
	res, err := man.cacheGet("example.org")
	if err != nil {
		t.Fatalf("man.cacheGet: %v", err)
	}
	if res == nil {
		t.Fatal("res is nil")
	}

	priv, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	dummy, err := dummyCert("dummy")
	if err != nil {
		t.Fatalf("dummyCert: %v", err)
	}
	tt := []struct {
		key      string
		prv, pub []byte
	}{
		{"dummy", priv, dummy},
		{"bad1", priv, []byte{1}},
		{"bad2", []byte{1}, pub},
	}
	for i, test := range tt {
		var buf bytes.Buffer
		pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: test.prv}
		if err := pem.Encode(&buf, pb); err != nil {
			t.Errorf("%d: pem.Encode: %v", i, err)
		}
		pb = &pem.Block{Type: "CERTIFICATE", Bytes: test.pub}
		if err := pem.Encode(&buf, pb); err != nil {
			t.Errorf("%d: pem.Encode: %v", i, err)
		}

		cache.Put(nil, test.key, buf.Bytes())
		if _, err := man.cacheGet(test.key); err == nil {
			t.Errorf("%d: err is nil", i)
		}
	}
}

func TestHostWhitelist(t *testing.T) {
	policy := HostWhitelist("example.com", "example.org", "*.example.net")
	tt := []struct {
		host  string
		allow bool
	}{
		{"example.com", true},
		{"example.org", true},
		{"one.example.com", false},
		{"two.example.org", false},
		{"three.example.net", false},
		{"dummy", false},
	}
	for i, test := range tt {
		err := policy(nil, test.host)
		if err != nil && test.allow {
			t.Errorf("%d: policy(%q): %v; want nil", i, test.host, err)
		}
		if err == nil && !test.allow {
			t.Errorf("%d: policy(%q): nil; want an error", i, test.host)
		}
	}
}
