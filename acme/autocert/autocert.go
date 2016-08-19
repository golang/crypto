// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package autocert provides automatic access to certificates from Let's Encrypt
// and any other ACME-based CA.
//
// This package is a work in progress and makes no API stability promises.
package autocert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/internal/acme"
	"golang.org/x/net/context"
)

// AcceptTOS always returns true to indicate the acceptance of a CA Terms of Service
// during account registration.
func AcceptTOS(tosURL string) bool { return true }

// HostPolicy specifies which host names the Manager is allowed to respond to.
// It returns a non-nil error if the host should be rejected.
// The returned error is accessible via tls.Conn.Handshake and its callers.
// See Manager's HostPolicy field and GetCertificate method docs for more details.
type HostPolicy func(ctx context.Context, host string) error

// HostWhitelist returns a policy where only the specified host names are allowed.
// Only exact matches are currently supported. Subdomains, regexp or wildcard
// will not match.
func HostWhitelist(hosts ...string) HostPolicy {
	whitelist := make(map[string]bool, len(hosts))
	for _, h := range hosts {
		whitelist[h] = true
	}
	return func(_ context.Context, host string) error {
		if !whitelist[host] {
			return errors.New("acme/autocert: host not configured")
		}
		return nil
	}
}

// defaultHostPolicy is used when Manager.HostPolicy is not set.
func defaultHostPolicy(context.Context, string) error {
	return nil
}

// Manager is a stateful certificate manager built on top of acme.Client.
// It obtains and refreshes certificates automatically,
// as well as providing them to a TLS server via tls.Config.
//
// A simple usage example:
//
//	m := autocert.Manager{
//		Prompt: autocert.AcceptTOS,
//		HostPolicy: autocert.HostWhitelist("example.org"),
//	}
//	s := &http.Server{
//		Addr: ":https",
//		TLSConfig: &tls.Config{GetCertificate: m.GetCertificate},
//	}
//	s.ListenAndServeTLS("", "")
//
// To preserve issued certificates and improve overall performance,
// use a cache implementation of Cache. For instance, DirCache.
type Manager struct {
	// Prompt specifies a callback function to conditionally accept a CA's Terms of Service (TOS).
	// The registration may require the caller to agree to the CA's TOS.
	// If so, Manager calls Prompt with a TOS URL provided by the CA. Prompt should report
	// whether the caller agrees to the terms.
	//
	// To always accept the terms, the callers can use AcceptTOS.
	Prompt func(tosURL string) bool

	// Cache optionally stores and retrieves previously-obtained certificates.
	// If nil, certs will only be cached for the lifetime of the Manager.
	//
	// Manager passes the Cache certificates data encoded in PEM, with private/public
	// parts combined in a single Cache.Put call, private key first.
	Cache Cache

	// HostPolicy controls which domains the Manager will attempt
	// to retrieve new certificates for. It does not affect cached certs.
	//
	// If non-nil, HostPolicy is called before requesting a new cert.
	// If nil, all hosts are currently allowed. This is not recommended,
	// as it opens a potential attack where clients connect to a server
	// by IP address and pretend to be asking for an incorrect host name.
	// Manager will attempt to obtain a certificate for that host, incorrectly,
	// eventually reaching the CA's rate limit for certificate requests
	// and making it impossible to obtain actual certificates.
	//
	// See GetCertificate for more details.
	HostPolicy HostPolicy

	// Client is used to perform low-level operations, such as account registration
	// and requesting new certificates.
	// If Client is nil, a zero-value acme.Client is used with acme.LetsEncryptURL
	// directory endpoint and a newly-generated 2048-bit RSA key.
	//
	// Mutating the field after the first call of GetCertificate method will have no effect.
	Client *acme.Client

	// Email optionally specifies a contact email address.
	// This is used by CAs, such as Let's Encrypt, to notify about problems
	// with issued certificates.
	//
	// If the Client's account key is already registered, Email is not used.
	Email string

	clientMu sync.Mutex
	client   *acme.Client // initialized by acmeClient method

	stateMu sync.Mutex
	state   map[string]*certState // keyed by domain name

	// tokenCert is keyed by token domain name, which matches server name
	// of ClientHello. Keys always have ".acme.invalid" suffix.
	tokenCertMu sync.RWMutex
	tokenCert   map[string]*tls.Certificate
}

// GetCertificate implements the tls.Config.GetCertificate hook.
// It provides a TLS certificate for hello.ServerName host, including answering
// *.acme.invalid (TLS-SNI) challenges. All other fields of hello are ignored.
//
// If m.HostPolicy is non-nil, GetCertificate calls the policy before requesting
// a new cert. A non-nil error returned from m.HostPolicy halts TLS negotiation.
// The error is propagated back to the caller of GetCertificate and is user-visible.
// This does not affect cached certs. See HostPolicy field description for more details.
func (m *Manager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if name == "" {
		return nil, errors.New("acme/autocert: missing server name")
	}

	// check whether this is a token cert requested for TLS-SNI challenge
	if strings.HasSuffix(name, ".acme.invalid") {
		m.tokenCertMu.RLock()
		defer m.tokenCertMu.RUnlock()
		if cert := m.tokenCert[name]; cert != nil {
			return cert, nil
		}
		if cert, err := m.cacheGet(name); err == nil {
			return cert, nil
		}
		// TODO: cache error results?
		return nil, fmt.Errorf("acme/autocert: no token cert for %q", name)
	}

	// regular domain
	cert, err := m.cert(name)
	if err == nil {
		return cert, nil
	}
	if err != ErrCacheMiss {
		return nil, err
	}

	// first-time
	ctx := context.Background() // TODO: use a deadline?
	if err := m.hostPolicy()(ctx, name); err != nil {
		return nil, err
	}
	cert, err = m.createCert(ctx, name)
	if err != nil {
		return nil, err
	}
	m.cachePut(name, cert)
	return cert, nil
}

// cert returns an existing certificate either from m.state or cache.
// If a certificate is found in cache but not in m.state, the latter will be filled
// with the cached value.
func (m *Manager) cert(name string) (*tls.Certificate, error) {
	m.stateMu.Lock()
	s, ok := m.state[name]
	if ok {
		m.stateMu.Unlock()
		s.RLock()
		defer s.RUnlock()
		return s.tlscert()
	}
	defer m.stateMu.Unlock()
	cert, err := m.cacheGet(name)
	if err != nil {
		return nil, err
	}
	signer, ok := cert.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, errors.New("acme/autocert: private key cannot sign")
	}
	if m.state == nil {
		m.state = make(map[string]*certState)
	}
	m.state[name] = &certState{
		key:  signer,
		cert: cert.Certificate,
		leaf: cert.Leaf,
	}
	return cert, nil
}

// cacheGet always returns a valid certificate, or an error otherwise.
func (m *Manager) cacheGet(domain string) (*tls.Certificate, error) {
	if m.Cache == nil {
		return nil, ErrCacheMiss
	}
	// TODO: might want to define a cache timeout on m
	ctx := context.Background()
	data, err := m.Cache.Get(ctx, domain)
	if err != nil {
		return nil, err
	}

	// private
	priv, pub := pem.Decode(data)
	if priv == nil || !strings.Contains(priv.Type, "PRIVATE") {
		return nil, errors.New("acme/autocert: no private key found in cache")
	}
	privKey, err := parsePrivateKey(priv.Bytes)
	if err != nil {
		return nil, err
	}

	// public
	var pubDER []byte
	for len(pub) > 0 {
		var b *pem.Block
		b, pub = pem.Decode(pub)
		if b == nil {
			break
		}
		pubDER = append(pubDER, b.Bytes...)
	}
	if len(pub) > 0 {
		return nil, errors.New("acme/autocert: invalid public key")
	}

	// parse public part(s) and verify the leaf is not expired
	// and corresponds to the private key
	x509Cert, err := x509.ParseCertificates(pubDER)
	if len(x509Cert) == 0 {
		return nil, errors.New("acme/autocert: no public key found in cache")
	}
	leaf := x509Cert[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return nil, errors.New("acme/autocert: certificate is not valid yet")
	}
	if now.After(leaf.NotAfter) {
		return nil, errors.New("acme/autocert: expired certificate")
	}
	if !domainMatch(leaf, domain) {
		return nil, errors.New("acme/autocert: certificate does not match domain name")
	}
	switch pub := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		prv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.N.Cmp(prv.N) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	case *ecdsa.PublicKey:
		prv, ok := privKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("acme/autocert: private key type does not match public key type")
		}
		if pub.X.Cmp(prv.X) != 0 || pub.Y.Cmp(prv.Y) != 0 {
			return nil, errors.New("acme/autocert: private key does not match public key")
		}
	default:
		return nil, errors.New("acme/autocert: unknown public key algorithm")
	}

	tlscert := &tls.Certificate{
		Certificate: make([][]byte, len(x509Cert)),
		PrivateKey:  privKey,
		Leaf:        leaf,
	}
	for i, crt := range x509Cert {
		tlscert.Certificate[i] = crt.Raw
	}
	return tlscert, nil
}

func (m *Manager) cachePut(domain string, tlscert *tls.Certificate) error {
	if m.Cache == nil {
		return nil
	}

	// contains PEM-encoded data
	var buf bytes.Buffer

	// private
	switch key := tlscert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		pb := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			return err
		}
	case *rsa.PrivateKey:
		b := x509.MarshalPKCS1PrivateKey(key)
		pb := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			return err
		}
	default:
		return errors.New("acme/autocert: unknown private key type")
	}

	// public
	for _, b := range tlscert.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			return err
		}
	}

	// TODO: might want to define a cache timeout on m
	ctx := context.Background()
	return m.Cache.Put(ctx, domain, buf.Bytes())
}

// createCert starts domain ownership verification and returns a certificate for that domain
// upon success.
//
// If the domain is already being verified, it waits for the existing verification to complete.
// Either way, createCert blocks for the duration of the whole process.
func (m *Manager) createCert(ctx context.Context, domain string) (*tls.Certificate, error) {
	state, ok, err := m.certState(domain)
	if err != nil {
		return nil, err
	}
	// state may exist if another goroutine is already working on it
	// in which case just wait for it to finish
	if ok {
		state.RLock()
		defer state.RUnlock()
		return state.tlscert()
	}

	// We are the first.
	// Unblock the readers when domain ownership is verified
	// and the we got the cert or the process failed.
	defer state.Unlock()
	// TODO: make m.verify retry or retry m.verify calls here
	if err := m.verify(ctx, domain); err != nil {
		return nil, err
	}
	client, err := m.acmeClient(ctx)
	if err != nil {
		return nil, err
	}
	csr, err := certRequest(state.key, domain)
	if err != nil {
		return nil, err
	}
	der, _, err := client.CreateCert(ctx, csr, 0, true)
	if err != nil {
		return nil, err
	}
	state.cert = der
	return state.tlscert()
}

// verify starts a new identifier (domain) authorization flow.
// It prepares a challenge response and then blocks until the authorization
// is marked as "completed" by the CA (either succeeded or failed).
//
// verify returns nil iff the verification was successful.
func (m *Manager) verify(ctx context.Context, domain string) error {
	client, err := m.acmeClient(ctx)
	if err != nil {
		return err
	}

	// start domain authorization and get the challenge
	authz, err := client.Authorize(ctx, domain)
	if err != nil {
		return err
	}
	// maybe don't need to at all
	if authz.Status == acme.StatusValid {
		return nil
	}

	// pick a challenge: prefer tls-sni-02 over tls-sni-01
	// TODO: consider authz.Combinations
	var chal *acme.Challenge
	for _, c := range authz.Challenges {
		if c.Type == "tls-sni-02" {
			chal = c
			break
		}
		if c.Type == "tls-sni-01" {
			chal = c
		}
	}
	if chal == nil {
		return errors.New("acme/autocert: no supported challenge type found")
	}

	// create a token cert for the challenge response
	var (
		cert tls.Certificate
		name string
	)
	switch chal.Type {
	case "tls-sni-01":
		cert, name, err = client.TLSSNI01ChallengeCert(chal.Token)
	case "tls-sni-02":
		cert, name, err = client.TLSSNI02ChallengeCert(chal.Token)
	default:
		err = fmt.Errorf("acme/autocert: unknown challenge type %q", chal.Type)
	}
	if err != nil {
		return err
	}
	m.putTokenCert(name, &cert)
	defer func() {
		// verification has ended at this point
		// don't need token cert anymore
		go m.deleteTokenCert(name)
	}()

	// ready to fulfill the challenge
	if _, err := client.Accept(ctx, chal); err != nil {
		return err
	}
	// wait for the CA to validate
	_, err = client.WaitAuthorization(ctx, authz.URI)
	return err
}

// certState returns existing state or creates a new one locked for read/write.
// The boolean return value indicates whether the state was found in m.state.
func (m *Manager) certState(domain string) (*certState, bool, error) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	if m.state == nil {
		m.state = make(map[string]*certState)
	}
	// existing state
	if state, ok := m.state[domain]; ok {
		return state, true, nil
	}
	// new locked state
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, false, err
	}
	state := &certState{key: key}
	state.Lock()
	m.state[domain] = state
	return state, false, nil
}

// putTokenCert stores the cert under the named key in both m.tokenCert map
// and m.Cache.
func (m *Manager) putTokenCert(name string, cert *tls.Certificate) {
	m.tokenCertMu.Lock()
	defer m.tokenCertMu.Unlock()
	if m.tokenCert == nil {
		m.tokenCert = make(map[string]*tls.Certificate)
	}
	m.tokenCert[name] = cert
	m.cachePut(name, cert)
}

// deleteTokenCert removes the token certificate for the specified domain name
// from both m.tokenCert map and m.Cache.
func (m *Manager) deleteTokenCert(name string) {
	m.tokenCertMu.Lock()
	defer m.tokenCertMu.Unlock()
	delete(m.tokenCert, name)
	if m.Cache != nil {
		m.Cache.Delete(context.Background(), name)
	}
}

func (m *Manager) acmeClient(ctx context.Context) (*acme.Client, error) {
	m.clientMu.Lock()
	defer m.clientMu.Unlock()
	if m.client != nil {
		return m.client, nil
	}

	client := m.Client
	if client == nil {
		client = &acme.Client{DirectoryURL: acme.LetsEncryptURL}
	}
	if client.Key == nil {
		var err error
		client.Key, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
	}
	var contact []string
	if m.Email != "" {
		contact = []string{"mailto:" + m.Email}
	}
	a := &acme.Account{Contact: contact}
	_, err := client.Register(ctx, a, m.Prompt)
	if ae, ok := err.(*acme.Error); err == nil || ok && ae.StatusCode == http.StatusConflict {
		// conflict indicates the key is already registered
		m.client = client
		err = nil
	}
	return m.client, err
}

func (m *Manager) hostPolicy() HostPolicy {
	if m.HostPolicy != nil {
		return m.HostPolicy
	}
	return defaultHostPolicy
}

// certState is ready when its mutex is unlocked for reading.
type certState struct {
	sync.RWMutex
	key  crypto.Signer
	cert [][]byte          // DER encoding
	leaf *x509.Certificate // parsed cert[0]; may be nil
}

// tlscert creates a tls.Certificate from s.key and s.cert.
// Callers should wrap it in s.RLock() and s.RUnlock().
func (s *certState) tlscert() (*tls.Certificate, error) {
	if s.key == nil {
		return nil, errors.New("acme/autocert: missing signer")
	}
	if len(s.cert) == 0 {
		return nil, errors.New("acme/autocert: missing certificate")
	}
	// TODO: compare pub.N with key.N or pub.{X,Y} for ECDSA?
	return &tls.Certificate{
		PrivateKey:  s.key,
		Certificate: s.cert,
		Leaf:        s.leaf,
	}, nil
}

// certRequest creates a certificate request for the given common name cn
// and optional SANs.
func certRequest(key crypto.Signer, cn string, san ...string) ([]byte, error) {
	req := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: san,
	}
	return x509.CreateCertificateRequest(rand.Reader, req, key)
}

// Attempt to parse the given private key DER block. OpenSSL 0.9.8 generates
// PKCS#1 private keys by default, while OpenSSL 1.0.0 generates PKCS#8 keys.
// OpenSSL ecparam generates SEC1 EC private keys for ECDSA. We try all three.
//
// Copied from crypto/tls/tls.go.
func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, errors.New("acme/autocert: found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("acme/autocert: failed to parse private key")
}

// domainMatch matches cert against the specified domain name.
// It doesn't support wildcard.
func domainMatch(cert *x509.Certificate, name string) bool {
	if cert.Subject.CommonName == name {
		return true
	}
	sort.Strings(cert.DNSNames)
	i := sort.SearchStrings(cert.DNSNames, name)
	return i < len(cert.DNSNames) && cert.DNSNames[i] == name
}

func retryAfter(v string) time.Duration {
	if i, err := strconv.Atoi(v); err == nil {
		return time.Duration(i) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return t.Sub(time.Now())
	}
	return time.Second
}
