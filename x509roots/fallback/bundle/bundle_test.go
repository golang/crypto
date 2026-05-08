// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bundle

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"regexp"
	"testing"
)

func TestBundle(t *testing.T) {
	for i, unparsed := range unparsedCertificates {
		cert, err := x509.ParseCertificate(rawCerts[unparsed.certStartOff : unparsed.certStartOff+unparsed.certLength])
		if err != nil {
			t.Errorf("ParseCertificate(unparsedCertificates[%v]) unexpected error: %v", i, err)
			continue
		}

		if !subjectsEqual(unparsed.cn, cert.Subject.String()) {
			t.Errorf("unparsedCertificates[%v].cn = %q; want = %q", i, unparsed.cn, cert.Subject.String())
		}

		sum := sha256.Sum256(cert.Raw)
		sumHex := hex.EncodeToString(sum[:])
		if sumHex != unparsed.sha256Hash {
			t.Errorf("unparsedCertificates[%v].sha256Hash = %q; want = %q", i, unparsed.sha256Hash, sumHex)
		}
	}
}

// subjectsEqual reports whether two RFC 2253 DN strings match.
//
// It tolerates the rendering difference introduced in Go 1.27, where
// string-typed attribute values for OIDs outside attributeTypeNames are
// rendered as strings rather than hex-encoded DER (see Go CL 773800).
//
// This can be removed when Go 1.25/1.26 are no longer supported.
func subjectsEqual(a, b string) bool {
	return a == b || normalizeHexValues(a) == normalizeHexValues(b)
}

// normalizeHexValues rewrites any "oid=#hex" to the equivalent "oid=value"
// rendering produced by Go 1.27+.
func normalizeHexValues(s string) string {
	return hexAttrRE.ReplaceAllStringFunc(s, func(match string) string {
		m := hexAttrRE.FindStringSubmatch(match)
		der, err := hex.DecodeString(m[2])
		if err != nil {
			return match
		}
		var v string
		if rest, err := asn1.Unmarshal(der, &v); err != nil || len(rest) != 0 {
			return match
		}
		return m[1] + "=" + v
	})
}

// hexAttrRE matches a "oid=#hex" attribute value in an RFC 2253 DN string.
var hexAttrRE = regexp.MustCompile(`([\d.]+)=#([[:xdigit:]]+)`)
