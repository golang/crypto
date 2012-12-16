// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"time"
)

// These constants from [PROTOCOL.certkeys] represent the algorithm names
// for certificate types supported by this package.
const (
	CertAlgoRSAv01      = "ssh-rsa-cert-v01@openssh.com"
	CertAlgoDSAv01      = "ssh-dss-cert-v01@openssh.com"
	CertAlgoECDSA256v01 = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	CertAlgoECDSA384v01 = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	CertAlgoECDSA521v01 = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
)

// Certificate types are used to specify whether a certificate is for identification
// of a user or a host.  Current identities are defined in [PROTOCOL.certkeys].
const (
	UserCert = 1
	HostCert = 2
)

type signature struct {
	Format string
	Blob   []byte
}

type tuple struct {
	Name string
	Data string
}

// An OpenSSHCertV01 represents an OpenSSH certificate as defined in
// [PROTOCOL.certkeys]?rev=1.8.
type OpenSSHCertV01 struct {
	Nonce                   []byte
	Key                     interface{} // rsa, dsa, or ecdsa *PublicKey
	Serial                  uint64
	Type                    uint32
	KeyId                   string
	ValidPrincipals         []string
	ValidAfter, ValidBefore time.Time
	CriticalOptions         []tuple
	Extensions              []tuple
	Reserved                []byte
	SignatureKey            interface{} // rsa, dsa, or ecdsa *PublicKey
	Signature               *signature
}

func parseOpenSSHCertV01(in []byte, algo string) (out *OpenSSHCertV01, rest []byte, ok bool) {
	cert := new(OpenSSHCertV01)

	if cert.Nonce, in, ok = parseString(in); !ok {
		return
	}

	switch algo {
	case CertAlgoRSAv01:
		var rsaPubKey *rsa.PublicKey
		if rsaPubKey, in, ok = parseRSA(in); !ok {
			return
		}
		cert.Key = rsaPubKey
	case CertAlgoDSAv01:
		var dsaPubKey *dsa.PublicKey
		if dsaPubKey, in, ok = parseDSA(in); !ok {
			return
		}
		cert.Key = dsaPubKey
	case CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01:
		var ecdsaPubKey *ecdsa.PublicKey
		if ecdsaPubKey, in, ok = parseECDSA(in); !ok {
			return
		}
		cert.Key = ecdsaPubKey
	default:
		ok = false
		return
	}

	if cert.Serial, in, ok = parseUint64(in); !ok {
		return
	}

	if cert.Type, in, ok = parseUint32(in); !ok || cert.Type != UserCert && cert.Type != HostCert {
		return
	}

	keyId, in, ok := parseString(in)
	if !ok {
		return
	}
	cert.KeyId = string(keyId)

	if cert.ValidPrincipals, in, ok = parseLengthPrefixedNameList(in); !ok {
		return
	}

	va, in, ok := parseUint64(in)
	if !ok {
		return
	}
	cert.ValidAfter = time.Unix(int64(va), 0)

	vb, in, ok := parseUint64(in)
	if !ok {
		return
	}
	cert.ValidBefore = time.Unix(int64(vb), 0)

	if cert.CriticalOptions, in, ok = parseTupleList(in); !ok {
		return
	}

	if cert.Extensions, in, ok = parseTupleList(in); !ok {
		return
	}

	if cert.Reserved, in, ok = parseString(in); !ok {
		return
	}

	sigKey, in, ok := parseString(in)
	if !ok {
		return
	}
	if cert.SignatureKey, _, ok = parsePubKey(sigKey); !ok {
		return
	}

	if cert.Signature, in, ok = parseSignature(in); !ok {
		return
	}

	ok = true
	return cert, in, ok
}

func marshalOpenSSHCertV01(cert *OpenSSHCertV01) []byte {
	var pubKey []byte
	switch cert.Key.(type) {
	case *rsa.PublicKey:
		k := cert.Key.(*rsa.PublicKey)
		pubKey = marshalPubRSA(k)
	case *dsa.PublicKey:
		k := cert.Key.(*dsa.PublicKey)
		pubKey = marshalPubDSA(k)
	case *ecdsa.PublicKey:
		k := cert.Key.(*ecdsa.PublicKey)
		pubKey = marshalPubECDSA(k)
	default:
		panic("ssh: unknown public key type in cert")
	}

	sigKey := serializePublickey(cert.SignatureKey)

	length := stringLength(len(cert.Nonce))
	length += len(pubKey)
	length += 8 // Length of Serial
	length += 4 // Length of Type
	length += stringLength(len(cert.KeyId))
	length += lengthPrefixedNameListLength(cert.ValidPrincipals)
	length += 8 // Length of ValidAfter
	length += 8 // Length of ValidBefore
	length += tupleListLength(cert.CriticalOptions)
	length += tupleListLength(cert.Extensions)
	length += stringLength(len(cert.Reserved))
	length += stringLength(len(sigKey))
	length += signatureLength(cert.Signature)

	ret := make([]byte, length)
	r := marshalString(ret, cert.Nonce)
	copy(r, pubKey)
	r = r[len(pubKey):]
	r = marshalUint64(r, cert.Serial)
	r = marshalUint32(r, cert.Type)
	r = marshalString(r, []byte(cert.KeyId))
	r = marshalLengthPrefixedNameList(r, cert.ValidPrincipals)
	r = marshalUint64(r, uint64(cert.ValidAfter.Unix()))
	r = marshalUint64(r, uint64(cert.ValidBefore.Unix()))
	r = marshalTupleList(r, cert.CriticalOptions)
	r = marshalTupleList(r, cert.Extensions)
	r = marshalString(r, cert.Reserved)
	r = marshalString(r, sigKey)
	r = marshalSignature(r, cert.Signature)
	if len(r) > 0 {
		panic("internal error")
	}
	return ret
}

func lengthPrefixedNameListLength(namelist []string) int {
	length := 4 // length prefix for list
	for _, name := range namelist {
		length += 4 // length prefix for name
		length += len(name)
	}
	return length
}

func marshalLengthPrefixedNameList(to []byte, namelist []string) []byte {
	length := uint32(lengthPrefixedNameListLength(namelist) - 4)
	to = marshalUint32(to, length)
	for _, name := range namelist {
		to = marshalString(to, []byte(name))
	}
	return to
}

func parseLengthPrefixedNameList(in []byte) (out []string, rest []byte, ok bool) {
	list, rest, ok := parseString(in)
	if !ok {
		return
	}

	for len(list) > 0 {
		var next []byte
		if next, list, ok = parseString(list); !ok {
			return nil, nil, false
		}
		out = append(out, string(next))
	}
	ok = true
	return
}

func tupleListLength(tupleList []tuple) int {
	length := 4 // length prefix for list
	for _, t := range tupleList {
		length += 4 // length prefix for t.Name
		length += len(t.Name)
		length += 4 // length prefix for t.Data
		length += len(t.Data)
	}
	return length
}

func marshalTupleList(to []byte, tuplelist []tuple) []byte {
	length := uint32(tupleListLength(tuplelist) - 4)
	to = marshalUint32(to, length)
	for _, t := range tuplelist {
		to = marshalString(to, []byte(t.Name))
		to = marshalString(to, []byte(t.Data))
	}
	return to
}

func parseTupleList(in []byte) (out []tuple, rest []byte, ok bool) {
	list, rest, ok := parseString(in)
	if !ok {
		return
	}

	for len(list) > 0 {
		var name, data []byte
		var ok bool
		name, list, ok = parseString(list)
		if !ok {
			return nil, nil, false
		}
		data, list, ok = parseString(list)
		if !ok {
			return nil, nil, false
		}
		out = append(out, tuple{string(name), string(data)})
	}
	ok = true
	return
}

func signatureLength(sig *signature) int {
	length := 4 // length prefix for signature
	length += stringLength(len(sig.Format))
	length += stringLength(len(sig.Blob))
	return length
}

func marshalSignature(to []byte, sig *signature) []byte {
	length := uint32(signatureLength(sig) - 4)
	to = marshalUint32(to, length)
	to = marshalString(to, []byte(sig.Format))
	to = marshalString(to, sig.Blob)
	return to
}

func parseSignature(in []byte) (out *signature, rest []byte, ok bool) {
	var sigBytes, format []byte
	sig := new(signature)

	if sigBytes, rest, ok = parseString(in); !ok {
		return
	}

	if format, sigBytes, ok = parseString(sigBytes); !ok {
		return
	}
	sig.Format = string(format)

	if sig.Blob, sigBytes, ok = parseString(sigBytes); !ok {
		return
	}

	return sig, rest, ok
}
