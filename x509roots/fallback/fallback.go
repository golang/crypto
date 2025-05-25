// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package fallback embeds a set of fallback X.509 trusted roots in the
// application by automatically invoking [x509.SetFallbackRoots]. This allows
// the application to work correctly even if the operating system does not
// provide a verifier or system roots pool.
//
// To use it, import the package like
//
//	import _ "golang.org/x/crypto/x509roots/fallback"
//
// It's recommended that only binaries, and not libraries, import this package.
//
// This package must be kept up to date for security and compatibility reasons.
// Use govulncheck to be notified of when new versions of the package are
// available.
package fallback

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

func init() {
	x509.SetFallbackRoots(newFallbackCertPool())
}

func newFallbackCertPool() *x509.CertPool {
	p := x509.NewCertPool()
	for _, c := range mustParse(unparsedCertificates) {
		if len(c.constraints) == 0 {
			p.AddCert(c.cert)
		} else {
			p.AddCertWithConstraint(c.cert, func(chain []*x509.Certificate) error {
				for _, constraint := range c.constraints {
					if err := constraint(chain); err != nil {
						return err
					}
				}
				return nil
			})
		}
	}
	return p
}

type unparsedCertificate struct {
	cn         string
	sha256Hash string
	pem        string

	// possible constraints
	distrustAfter string
}

type parsedCertificate struct {
	cert        *x509.Certificate
	constraints []func([]*x509.Certificate) error
}

func mustParse(unparsedCerts []unparsedCertificate) []parsedCertificate {
	var b []parsedCertificate
	for _, unparsed := range unparsedCerts {
		block, rest := pem.Decode([]byte(unparsed.pem))
		if block == nil {
			panic(fmt.Sprintf("unexpected nil PEM block for %q", unparsed.cn))
		}
		if len(rest) != 0 {
			panic(fmt.Sprintf("unexpected trailing data in PEM for %q", unparsed.cn))
		}
		if block.Type != "CERTIFICATE" {
			panic(fmt.Sprintf("unexpected PEM block type for %q: %s", unparsed.cn, block.Type))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		parsed := parsedCertificate{cert: cert}
		// parse possible constraints, this should check all fields of unparsedCertificate.
		if unparsed.distrustAfter != "" {
			distrustAfter, err := time.Parse(time.RFC3339, unparsed.distrustAfter)
			if err != nil {
				panic(fmt.Sprintf("failed to parse distrustAfter %q: %s", unparsed.distrustAfter, err))
			}
			parsed.constraints = append(parsed.constraints, func(chain []*x509.Certificate) error {
				for _, c := range chain {
					if c.NotBefore.After(distrustAfter) {
						return fmt.Errorf("certificate issued after distrust-after date %q", distrustAfter)
					}
				}
				return nil
			})
		}
		b = append(b, parsed)
	}
	return b
}
