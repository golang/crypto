// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// While contents of this file is pertinent only to RFC8555,
// it is complementary to the tests in the other _test.go files
// many of which are valid for both pre- and RFC8555.
// This will make it easier to clean up the tests once non-RFC compliant
// code is removed.

func TestRFC_Discover(t *testing.T) {
	const (
		nonce       = "https://example.com/acme/new-nonce"
		reg         = "https://example.com/acme/new-acct"
		order       = "https://example.com/acme/new-order"
		authz       = "https://example.com/acme/new-authz"
		revoke      = "https://example.com/acme/revoke-cert"
		keychange   = "https://example.com/acme/key-change"
		metaTerms   = "https://example.com/acme/terms/2017-5-30"
		metaWebsite = "https://www.example.com/"
		metaCAA     = "example.com"
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"newNonce": %q,
			"newAccount": %q,
			"newOrder": %q,
			"newAuthz": %q,
			"revokeCert": %q,
			"keyChange": %q,
			"meta": {
				"termsOfService": %q,
				"website": %q,
				"caaIdentities": [%q],
				"externalAccountRequired": true
			}
		}`, nonce, reg, order, authz, revoke, keychange, metaTerms, metaWebsite, metaCAA)
	}))
	defer ts.Close()
	c := Client{DirectoryURL: ts.URL}
	dir, err := c.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if dir.NonceURL != nonce {
		t.Errorf("dir.NonceURL = %q; want %q", dir.NonceURL, nonce)
	}
	if dir.RegURL != reg {
		t.Errorf("dir.RegURL = %q; want %q", dir.RegURL, reg)
	}
	if dir.OrderURL != order {
		t.Errorf("dir.OrderURL = %q; want %q", dir.OrderURL, order)
	}
	if dir.AuthzURL != authz {
		t.Errorf("dir.AuthzURL = %q; want %q", dir.AuthzURL, authz)
	}
	if dir.RevokeURL != revoke {
		t.Errorf("dir.RevokeURL = %q; want %q", dir.RevokeURL, revoke)
	}
	if dir.KeyChangeURL != keychange {
		t.Errorf("dir.KeyChangeURL = %q; want %q", dir.KeyChangeURL, keychange)
	}
	if dir.Terms != metaTerms {
		t.Errorf("dir.Terms = %q; want %q", dir.Terms, metaTerms)
	}
	if dir.Website != metaWebsite {
		t.Errorf("dir.Website = %q; want %q", dir.Website, metaWebsite)
	}
	if len(dir.CAA) == 0 || dir.CAA[0] != metaCAA {
		t.Errorf("dir.CAA = %q; want [%q]", dir.CAA, metaCAA)
	}
	if !dir.ExternalAccountRequired {
		t.Error("dir.Meta.ExternalAccountRequired is false")
	}
}
