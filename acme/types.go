// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ACME status values of Account, Order, Authorization and Challenge objects.
// See https://tools.ietf.org/html/rfc8555#section-7.1.6 for details.
const (
	StatusDeactivated = "deactivated"
	StatusExpired     = "expired"
	StatusInvalid     = "invalid"
	StatusPending     = "pending"
	StatusProcessing  = "processing"
	StatusReady       = "ready"
	StatusRevoked     = "revoked"
	StatusUnknown     = "unknown"
	StatusValid       = "valid"
)

// CRLReasonCode identifies the reason for a certificate revocation.
type CRLReasonCode int

// CRL reason codes as defined in RFC 5280.
const (
	CRLReasonUnspecified          CRLReasonCode = 0
	CRLReasonKeyCompromise        CRLReasonCode = 1
	CRLReasonCACompromise         CRLReasonCode = 2
	CRLReasonAffiliationChanged   CRLReasonCode = 3
	CRLReasonSuperseded           CRLReasonCode = 4
	CRLReasonCessationOfOperation CRLReasonCode = 5
	CRLReasonCertificateHold      CRLReasonCode = 6
	CRLReasonRemoveFromCRL        CRLReasonCode = 8
	CRLReasonPrivilegeWithdrawn   CRLReasonCode = 9
	CRLReasonAACompromise         CRLReasonCode = 10
)

var (
	// ErrUnsupportedKey is returned when an unsupported key type is encountered.
	ErrUnsupportedKey = errors.New("acme: unknown key type; only RSA and ECDSA are supported")

	// ErrAccountAlreadyExists indicates that the Client's key has already been registered
	// with the CA. It is returned by Register method.
	ErrAccountAlreadyExists = errors.New("acme: account already exists")

	// ErrNoAccount indicates that the Client's key has not been registered with the CA.
	ErrNoAccount = errors.New("acme: account does not exist")
)

// ProblemDetails is an ACME Problem Details Document.
// https://tools.ietf.org/html/rfc7807 with the subproblems ACMEv2 extension.
type ProblemDetails struct {
	// StatusCode is The HTTP status code generated by the origin server.
	StatusCode int
	// ProblemType is a URI reference that identifies the problem type,
	// typically in a "urn:acme:error:xxx" form.
	ProblemType string `json:"type"`
	// Detail is a human-readable explanation specific to this occurrence of the problem.
	Detail string
	// Instance indicates a URL that the client should direct a human user to visit
	// in order for instructions on how to agree to the updated Terms of Service.
	// In such an event CA sets StatusCode to 403, ProblemType to
	// "urn:ietf:params:acme:error:userActionRequired" and a Link header with relation
	// "terms-of-service" containing the latest TOS URL.
	Instance string
}

// SubproblemDetails represents sub-problems specific to an identifier that are
// related to a top-level ProblemDetails.
// See RFC 8555 Section 6.7.1: https://tools.ietf.org/html/rfc8555#section-6.7.1
type SubproblemDetails struct {
	ProblemDetails
	Identifier *AuthzID
}

// Error is an ACME error, based on Problem Details for HTTP APIs doc
// https://tools.ietf.org/html/rfc7807
type Error struct {
	ProblemDetails
	// Subproblems are optional additional per-identifier problems.
	Subproblems []SubproblemDetails
	// Header is the original server error response headers.
	// It may be nil.
	Header http.Header
}

func (e *Error) Error() string {
	return fmt.Sprintf("%d %s: %s", e.StatusCode, e.ProblemType, e.Detail)
}

// AuthorizationError indicates that an authorization for an identifier
// did not succeed.
// It contains all errors from Challenge items of the failed Authorization.
type AuthorizationError struct {
	// URI uniquely identifies the failed Authorization.
	URI string

	// Identifier is an AuthzID.Value of the failed Authorization.
	Identifier string

	// Errors is a collection of non-nil error values of Challenge items
	// of the failed Authorization.
	Errors []error
}

func (a *AuthorizationError) Error() string {
	e := make([]string, len(a.Errors))
	for i, err := range a.Errors {
		e[i] = err.Error()
	}

	if a.Identifier != "" {
		return fmt.Sprintf("acme: authorization error for %s: %s", a.Identifier, strings.Join(e, "; "))
	}

	return fmt.Sprintf("acme: authorization error: %s", strings.Join(e, "; "))
}

// OrderError is returned from Client's order related methods.
// It indicates the order is unusable and the clients should start over with
// AuthorizeOrder.
//
// The clients can still fetch the order object from CA using GetOrder
// to inspect its state.
type OrderError struct {
	OrderURL string
	Status   string
}

func (oe *OrderError) Error() string {
	return fmt.Sprintf("acme: order %s status: %s", oe.OrderURL, oe.Status)
}

// RateLimit reports whether err represents a rate limit error and
// any Retry-After duration returned by the server.
//
// See the following for more details on rate limiting:
// https://tools.ietf.org/html/draft-ietf-acme-acme-05#section-5.6
func RateLimit(err error) (time.Duration, bool) {
	e, ok := err.(*Error)
	if !ok {
		return 0, false
	}
	// Some CA implementations may return incorrect values.
	// Use case-insensitive comparison.
	if !strings.HasSuffix(strings.ToLower(e.ProblemType), ":ratelimited") {
		return 0, false
	}
	if e.Header == nil {
		return 0, true
	}
	return retryAfter(e.Header.Get("Retry-After")), true
}

// Account is a user account. It is associated with a private key.
// Non-RFC 8555 fields are empty when interfacing with a compliant CA.
type Account struct {
	// URI is the account unique ID, which is also a URL used to retrieve
	// account data from the CA.
	// When interfacing with RFC 8555-compliant CAs, URI is the "kid" field
	// value in JWS signed requests.
	URI string

	// Contact is a slice of contact info used during registration.
	// See https://tools.ietf.org/html/rfc8555#section-7.3 for supported
	// formats.
	Contact []string

	// Status indicates current account status as returned by the CA.
	// Possible values are StatusValid, StatusDeactivated, and StatusRevoked.
	Status string

	// OrdersURL is a URL from which a list of orders submitted by this account
	// can be fetched.
	OrdersURL string

	// The terms user has agreed to.
	// A value not matching CurrentTerms indicates that the user hasn't agreed
	// to the actual Terms of Service of the CA.
	//
	// It is non-RFC 8555 compliant. Package users can store the ToS they agree to
	// during Client's Register call in the prompt callback function.
	AgreedTerms string

	// Actual terms of a CA.
	//
	// It is non-RFC 8555 compliant. Use Directory's Terms field.
	// When a CA updates their terms and requires an account agreement,
	// a URL at which instructions to do so is available in Error's Instance field.
	CurrentTerms string

	// Authz is the authorization URL used to initiate a new authz flow.
	//
	// It is non-RFC 8555 compliant. Use Directory's AuthzURL or OrderURL.
	Authz string

	// Authorizations is a URI from which a list of authorizations
	// granted to this account can be fetched via a GET request.
	//
	// It is non-RFC 8555 compliant and is obsoleted by OrdersURL.
	Authorizations string

	// Certificates is a URI from which a list of certificates
	// issued for this account can be fetched via a GET request.
	//
	// It is non-RFC 8555 compliant and is obsoleted by OrdersURL.
	Certificates string
}

// Directory is ACME server discovery data.
// See https://tools.ietf.org/html/rfc8555#section-7.1.1 for more details.
type Directory struct {
	// NonceURL indicates an endpoint where to fetch fresh nonce values from.
	NonceURL string

	// RegURL is an account endpoint URL, allowing for creating new accounts.
	// Pre-RFC 8555 CAs also allow modifying existing accounts at this URL.
	RegURL string

	// OrderURL is used to initiate the certificate issuance flow
	// as described in RFC 8555.
	OrderURL string

	// AuthzURL is used to initiate identifier pre-authorization flow.
	// Empty string indicates the flow is unsupported by the CA.
	AuthzURL string

	// CertURL is a new certificate issuance endpoint URL.
	// It is non-RFC 8555 compliant and is obsoleted by OrderURL.
	CertURL string

	// RevokeURL is used to initiate a certificate revocation flow.
	RevokeURL string

	// KeyChangeURL allows to perform account key rollover flow.
	KeyChangeURL string

	// Term is a URI identifying the current terms of service.
	Terms string

	// Website is an HTTP or HTTPS URL locating a website
	// providing more information about the ACME server.
	Website string

	// CAA consists of lowercase hostname elements, which the ACME server
	// recognises as referring to itself for the purposes of CAA record validation
	// as defined in RFC6844.
	CAA []string

	// ExternalAccountRequired indicates that the CA requires for all account-related
	// requests to include external account binding information.
	ExternalAccountRequired bool
}

// rfcCompliant reports whether the ACME server implements RFC 8555.
// Note that some servers may have incomplete RFC implementation
// even if the returned value is true.
// If rfcCompliant reports false, the server most likely implements draft-02.
func (d *Directory) rfcCompliant() bool {
	return d.OrderURL != ""
}

// Order represents a client's request for a certificate.
// It tracks the request flow progress through to issuance.
type Order struct {
	// URI uniquely identifies an order.
	URI string

	// Status represents the current status of the order.
	// It indicates which action the client should take.
	//
	// Possible values are StatusPending, StatusReady, StatusProcessing, StatusValid and StatusInvalid.
	// Pending means the CA does not believe that the client has fulfilled the requirements.
	// Ready indicates that the client has fulfilled all the requirements and can submit a CSR
	// to obtain a certificate. This is done with Client's CreateOrderCert.
	// Processing means the certificate is being issued.
	// Valid indicates the CA has issued the certificate. It can be downloaded
	// from the Order's CertURL. This is done with Client's FetchCert.
	// Invalid means the certificate will not be issued. Users should consider this order
	// abandoned.
	Status string

	// Expires is the timestamp after which CA considers this order invalid.
	Expires time.Time

	// Identifiers contains all identifier objects which the order pertains to.
	Identifiers []AuthzID

	// NotBefore is the requested value of the notBefore field in the certificate.
	NotBefore time.Time

	// NotAfter is the requested value of the notAfter field in the certificate.
	NotAfter time.Time

	// AuthzURLs represents authorizations to complete before a certificate
	// for identifiers specified in the order can be issued.
	// It also contains unexpired authorizations that the client has completed
	// in the past.
	//
	// Authorization objects can be fetched using Client's GetAuthorization method.
	//
	// The required authorizations are dictated by CA policies.
	// There may not be a 1:1 relationship between the identifiers and required authorizations.
	// Required authorizations can be identified by their StatusPending status.
	//
	// For orders in the StatusValid or StatusInvalid state these are the authorizations
	// which were completed.
	AuthzURLs []string

	// FinalizeURL is the endpoint at which a CSR is submitted to obtain a certificate
	// once all the authorizations are satisfied.
	FinalizeURL string

	// CertURL points to the certificate that has been issued in response to this order.
	CertURL string

	// The error that occurred while processing the order as received from a CA, if any.
	Error *Error
}

// OrderOption allows customizing Client.AuthorizeOrder call.
type OrderOption interface {
	privateOrderOpt()
}

// WithOrderNotBefore sets order's NotBefore field.
func WithOrderNotBefore(t time.Time) OrderOption {
	return orderNotBeforeOpt(t)
}

// WithOrderNotAfter sets order's NotAfter field.
func WithOrderNotAfter(t time.Time) OrderOption {
	return orderNotAfterOpt(t)
}

type orderNotBeforeOpt time.Time

func (orderNotBeforeOpt) privateOrderOpt() {}

type orderNotAfterOpt time.Time

func (orderNotAfterOpt) privateOrderOpt() {}

// Authorization encodes an authorization response.
type Authorization struct {
	// URI uniquely identifies a authorization.
	URI string

	// Status is the current status of an authorization.
	// Possible values are StatusPending, StatusValid, StatusInvalid, StatusDeactivated,
	// StatusExpired and StatusRevoked.
	Status string

	// Identifier is what the account is authorized to represent.
	Identifier AuthzID

	// The timestamp after which the CA considers the authorization invalid.
	Expires time.Time

	// Wildcard is true for authorizations of a wildcard domain name.
	Wildcard bool

	// Challenges that the client needs to fulfill in order to prove possession
	// of the identifier (for pending authorizations).
	// For valid authorizations, the challenge that was validated.
	// For invalid authorizations, the challenge that was attempted and failed.
	//
	// RFC 8555 compatible CAs require users to fuflfill only one of the challenges.
	Challenges []*Challenge

	// A collection of sets of challenges, each of which would be sufficient
	// to prove possession of the identifier.
	// Clients must complete a set of challenges that covers at least one set.
	// Challenges are identified by their indices in the challenges array.
	// If this field is empty, the client needs to complete all challenges.
	//
	// This field is unused in RFC 8555.
	Combinations [][]int
}

// AuthzID is an identifier that an account is authorized to represent.
type AuthzID struct {
	Type  string // The type of identifier, "dns" or "ip".
	Value string // The identifier itself, e.g. "example.org".
}

// DomainIDs creates a slice of AuthzID with "dns" identifier type.
func DomainIDs(names ...string) []AuthzID {
	a := make([]AuthzID, len(names))
	for i, v := range names {
		a[i] = AuthzID{Type: "dns", Value: v}
	}
	return a
}

// IPIDs creates a slice of AuthzID with "ip" identifier type.
// Each element of addr is textual form of an address as defined
// in RFC1123 Section 2.1 for IPv4 and in RFC5952 Section 4 for IPv6.
func IPIDs(addr ...string) []AuthzID {
	a := make([]AuthzID, len(addr))
	for i, v := range addr {
		a[i] = AuthzID{Type: "ip", Value: v}
	}
	return a
}

// wireAuthzID is ACME JSON representation of authorization identifier objects.
type wireAuthzID struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// wireAuthz is ACME JSON representation of Authorization objects.
type wireAuthz struct {
	Identifier   wireAuthzID
	Status       string
	Expires      time.Time
	Wildcard     bool
	Challenges   []wireChallenge
	Combinations [][]int
	Error        *wireError
}

func (z *wireAuthz) authorization(uri string) *Authorization {
	a := &Authorization{
		URI:          uri,
		Status:       z.Status,
		Identifier:   AuthzID{Type: z.Identifier.Type, Value: z.Identifier.Value},
		Expires:      z.Expires,
		Wildcard:     z.Wildcard,
		Challenges:   make([]*Challenge, len(z.Challenges)),
		Combinations: z.Combinations, // shallow copy
	}
	for i, v := range z.Challenges {
		a.Challenges[i] = v.challenge()
	}
	return a
}

func (z *wireAuthz) error(uri string) *AuthorizationError {
	err := &AuthorizationError{
		URI:        uri,
		Identifier: z.Identifier.Value,
	}

	if z.Error != nil {
		err.Errors = append(err.Errors, z.Error.error(nil))
	}

	for _, raw := range z.Challenges {
		if raw.Error != nil {
			err.Errors = append(err.Errors, raw.Error.error(nil))
		}
	}

	return err
}

// Challenge encodes a returned CA challenge.
// Its Error field may be non-nil if the challenge is part of an Authorization
// with StatusInvalid.
type Challenge struct {
	// Type is the challenge type, e.g. "http-01", "tls-alpn-01", "dns-01".
	Type string

	// URI is where a challenge response can be posted to.
	URI string

	// Token is a random value that uniquely identifies the challenge.
	Token string

	// Status identifies the status of this challenge.
	// In RFC 8555, possible values are StatusPending, StatusProcessing, StatusValid,
	// and StatusInvalid.
	Status string

	// Validated is the time at which the CA validated this challenge.
	// Always zero value in pre-RFC 8555.
	Validated time.Time

	// Error indicates the reason for an authorization failure
	// when this challenge was used.
	// The type of a non-nil value is *Error.
	Error error
}

// wireChallenge is ACME JSON challenge representation.
type wireChallenge struct {
	URL       string `json:"url"` // RFC
	URI       string `json:"uri"` // pre-RFC
	Type      string
	Token     string
	Status    string
	Validated time.Time
	Error     *wireError
}

func (c *wireChallenge) challenge() *Challenge {
	v := &Challenge{
		URI:    c.URL,
		Type:   c.Type,
		Token:  c.Token,
		Status: c.Status,
	}
	if v.URI == "" {
		v.URI = c.URI // c.URL was empty; use legacy
	}
	if v.Status == "" {
		v.Status = StatusPending
	}
	if c.Error != nil {
		v.Error = c.Error.error(nil)
	}
	return v
}

// wireError is a subset of fields of the Problem Details object
// as described in https://tools.ietf.org/html/rfc7807#section-3.1.
type wireError struct {
	Status      int
	Type        string
	Detail      string
	Instance    string
	Subproblems []SubproblemDetails
}

func (e *wireError) error(h http.Header) *Error {
	return &Error{
		ProblemDetails: ProblemDetails{
			StatusCode:  e.Status,
			ProblemType: e.Type,
			Detail:      e.Detail,
			Instance:    e.Instance,
		},
		Subproblems: e.Subproblems,
		Header: h,
	}
}

// CertOption is an optional argument type for the TLS ChallengeCert methods for
// customizing a temporary certificate for TLS-based challenges.
type CertOption interface {
	privateCertOpt()
}

// WithKey creates an option holding a private/public key pair.
// The private part signs a certificate, and the public part represents the signee.
func WithKey(key crypto.Signer) CertOption {
	return &certOptKey{key}
}

type certOptKey struct {
	key crypto.Signer
}

func (*certOptKey) privateCertOpt() {}

// WithTemplate creates an option for specifying a certificate template.
// See x509.CreateCertificate for template usage details.
//
// In TLS ChallengeCert methods, the template is also used as parent,
// resulting in a self-signed certificate.
// The DNSNames field of t is always overwritten for tls-sni challenge certs.
func WithTemplate(t *x509.Certificate) CertOption {
	return (*certOptTemplate)(t)
}

type certOptTemplate x509.Certificate

func (*certOptTemplate) privateCertOpt() {}
