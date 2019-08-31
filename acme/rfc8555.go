// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// DeactivateReg permanently disables an existing account associated with c.Key.
// A deactivated account can no longer request certificate issuance or access
// resources related to the account, such as orders or authorizations.
//
// It works only with RFC8555 compliant CAs.
func (c *Client) DeactivateReg(ctx context.Context) error {
	url := string(c.accountKID(ctx))
	if url == "" {
		return ErrNoAccount
	}
	req := json.RawMessage(`{"status": "deactivated"}`)
	res, err := c.post(ctx, nil, url, req, wantStatus(http.StatusOK))
	if err != nil {
		return err
	}
	res.Body.Close()
	return nil
}

// registerRFC is quivalent to c.Register but for RFC-compliant CAs.
// It expects c.Discover to have already been called.
// TODO: Implement externalAccountBinding.
func (c *Client) registerRFC(ctx context.Context, acct *Account, prompt func(tosURL string) bool) (*Account, error) {
	c.cacheMu.Lock() // guard c.kid access
	defer c.cacheMu.Unlock()

	req := struct {
		TermsAgreed bool     `json:"termsOfServiceAgreed,omitempty"`
		Contact     []string `json:"contact,omitempty"`
	}{
		Contact: acct.Contact,
	}
	if c.dir.Terms != "" {
		req.TermsAgreed = prompt(c.dir.Terms)
	}
	res, err := c.post(ctx, c.Key, c.dir.RegURL, req, wantStatus(
		http.StatusOK,      // account with this key already registered
		http.StatusCreated, // new account created
	))
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	a, err := responseAccount(res)
	if err != nil {
		return nil, err
	}
	// Cache Account URL even if we return an error to the caller.
	// It is by all means a valid and usable "kid" value for future requests.
	c.kid = keyID(a.URI)
	if res.StatusCode == http.StatusOK {
		return nil, ErrAccountAlreadyExists
	}
	return a, nil
}

// updateGegRFC is equivalent to c.UpdateReg but for RFC-compliant CAs.
// It expects c.Discover to have already been called.
func (c *Client) updateRegRFC(ctx context.Context, a *Account) (*Account, error) {
	url := string(c.accountKID(ctx))
	if url == "" {
		return nil, ErrNoAccount
	}
	req := struct {
		Contact []string `json:"contact,omitempty"`
	}{
		Contact: a.Contact,
	}
	res, err := c.post(ctx, nil, url, req, wantStatus(http.StatusOK))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return responseAccount(res)
}

// getGegRFC is equivalent to c.GetReg but for RFC-compliant CAs.
// It expects c.Discover to have already been called.
func (c *Client) getRegRFC(ctx context.Context) (*Account, error) {
	req := json.RawMessage(`{"onlyReturnExisting": true}`)
	res, err := c.post(ctx, c.Key, c.dir.RegURL, req, wantStatus(http.StatusOK))
	if e, ok := err.(*Error); ok && e.ProblemType == "urn:ietf:params:acme:error:accountDoesNotExist" {
		return nil, ErrNoAccount
	}
	if err != nil {
		return nil, err
	}

	defer res.Body.Close()
	return responseAccount(res)
}

func responseAccount(res *http.Response) (*Account, error) {
	var v struct {
		Status  string
		Contact []string
		Orders  string
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: invalid account response: %v", err)
	}
	return &Account{
		URI:       res.Header.Get("Location"),
		Status:    v.Status,
		Contact:   v.Contact,
		OrdersURL: v.Orders,
	}, nil
}

// AuthorizeOrder initiates the order-based application for certificate issuance,
// as opposed to pre-authorization in Authorize.
//
// The caller then needs to fetch each required authorization with GetAuthorization
// and fulfill a challenge using Accept. Once all authorizations are satisfied,
// the caller will typically want to poll order status using WaitOrder until it's in StatusReady state.
// To finalize the order and obtain a certificate, the caller submits a CSR with CreateOrderCert.
func (c *Client) AuthorizeOrder(ctx context.Context, id []AuthzID, opt ...OrderOption) (*Order, error) {
	dir, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}

	req := struct {
		Identifiers []wireAuthzID `json:"identifiers"`
		NotBefore   string        `json:"notBefore,omitempty"`
		NotAfter    string        `json:"notAfter,omitempty"`
	}{}
	for _, v := range id {
		req.Identifiers = append(req.Identifiers, wireAuthzID{
			Type:  v.Type,
			Value: v.Value,
		})
	}
	for _, o := range opt {
		switch o := o.(type) {
		case orderNotBeforeOpt:
			req.NotBefore = time.Time(o).Format(time.RFC3339)
		case orderNotAfterOpt:
			req.NotAfter = time.Time(o).Format(time.RFC3339)
		default:
			// Package's fault if we let this happen.
			panic(fmt.Sprintf("unsupported order option type %T", o))
		}
	}

	res, err := c.post(ctx, nil, dir.OrderURL, req, wantStatus(http.StatusCreated))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return responseOrder(res)
}

// GetOrder retrives an order identified by the given URL.
// For orders created with AuthorizeOrder, the url value is Order.URI.
//
// If a caller needs to poll an order until its status is final,
// see the WaitOrder method.
func (c *Client) GetOrder(ctx context.Context, url string) (*Order, error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}

	res, err := c.post(ctx, nil, url, noPayload, wantStatus(http.StatusOK))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	return responseOrder(res)
}

// WaitOrder polls an order from the given URL until it is in one of the final states,
// StatusReady, StatusValid or StatusInvalid, the CA responded with a non-retryable error
// or the context is done.
//
// It returns a non-nil Order only if its Status is StatusReady or StatusValid.
// In all other cases WaitOrder returns an error.
// If the Status is StatusInvalid, the returned error is of type *WaitOrderError.
func (c *Client) WaitOrder(ctx context.Context, url string) (*Order, error) {
	if _, err := c.Discover(ctx); err != nil {
		return nil, err
	}
	for {
		res, err := c.post(ctx, nil, url, noPayload, wantStatus(http.StatusOK))
		if err != nil {
			return nil, err
		}
		o, err := responseOrder(res)
		res.Body.Close()
		switch {
		case err != nil:
			// Skip and retry.
		case o.Status == StatusInvalid:
			return nil, &WaitOrderError{OrderURL: o.URI, Status: o.Status}
		case o.Status == StatusReady || o.Status == StatusValid:
			return o, nil
		}

		d := retryAfter(res.Header.Get("Retry-After"))
		if d == 0 {
			// Default retry-after.
			// Same reasoning as in WaitAuthorization.
			d = time.Second
		}
		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
			// Retry.
		}
	}
}

func responseOrder(res *http.Response) (*Order, error) {
	var v struct {
		Status         string
		Expires        time.Time
		Identifiers    []wireAuthzID
		NotBefore      time.Time
		NotAfter       time.Time
		Error          *wireError
		Authorizations []string
		Finalize       string
		Certificate    string
	}
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("acme: error reading order: %v", err)
	}
	o := &Order{
		URI:         res.Header.Get("Location"),
		Status:      v.Status,
		Expires:     v.Expires,
		NotBefore:   v.NotBefore,
		NotAfter:    v.NotAfter,
		AuthzURLs:   v.Authorizations,
		FinalizeURL: v.Finalize,
		CertURL:     v.Certificate,
	}
	for _, id := range v.Identifiers {
		o.Identifiers = append(o.Identifiers, AuthzID{Type: id.Type, Value: id.Value})
	}
	if v.Error != nil {
		o.Error = v.Error.error(nil /* headers */)
	}
	return o, nil
}
