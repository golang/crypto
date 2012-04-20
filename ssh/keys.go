// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/dsa"
	"crypto/rsa"
	"math/big"
)

// parsePubKey parses a public key according to RFC 4253, section 6.6.
func parsePubKey(in []byte) (out interface{}, rest []byte, ok bool) {
	algo, in, ok := parseString(in)
	if !ok {
		return
	}

	switch string(algo) {
	case hostAlgoRSA:
		return parseRSA(in)
	case hostAlgoDSA:
		return parseDSA(in)
	case hostAlgoRSACertV01, hostAlgoDSACertV01:
		return parseOpenSSHCertV01(in, string(algo))
	}
	panic("ssh: unknown public key type")
}

// parseRSA parses an RSA key according to RFC 4253, section 6.6.
func parseRSA(in []byte) (out *rsa.PublicKey, rest []byte, ok bool) {
	key := new(rsa.PublicKey)

	bigE, in, ok := parseInt(in)
	if !ok || bigE.BitLen() > 24 {
		return
	}
	e := bigE.Int64()
	if e < 3 || e&1 == 0 {
		ok = false
		return
	}
	key.E = int(e)

	if key.N, in, ok = parseInt(in); !ok {
		return
	}

	ok = true
	return key, in, ok
}

// parseDSA parses an DSA key according to RFC 4253, section 6.6.
func parseDSA(in []byte) (out *dsa.PublicKey, rest []byte, ok bool) {
	key := new(dsa.PublicKey)

	if key.P, in, ok = parseInt(in); !ok {
		return
	}

	if key.Q, in, ok = parseInt(in); !ok {
		return
	}

	if key.G, in, ok = parseInt(in); !ok {
		return
	}

	if key.Y, in, ok = parseInt(in); !ok {
		return
	}

	ok = true
	return key, in, ok
}

// marshalPrivRSA serializes an RSA private key according to RFC 4253, section 6.6.
func marshalPrivRSA(priv *rsa.PrivateKey) []byte {
	e := new(big.Int).SetInt64(int64(priv.E))
	length := stringLength(len(hostAlgoRSA))
	length += intLength(e)
	length += intLength(priv.N)

	ret := make([]byte, length)
	r := marshalString(ret, []byte(hostAlgoRSA))
	r = marshalInt(r, e)
	r = marshalInt(r, priv.N)

	return ret
}

// marshalPubRSA serializes an RSA public key according to RFC 4253, section 6.6.
func marshalPubRSA(key *rsa.PublicKey) []byte {
	e := new(big.Int).SetInt64(int64(key.E))
	length := intLength(e)
	length += intLength(key.N)

	ret := make([]byte, length)
	r := marshalInt(ret, e)
	r = marshalInt(r, key.N)

	return ret
}

// marshalPubDSA serializes an DSA public key according to RFC 4253, section 6.6.
func marshalPubDSA(key *dsa.PublicKey) []byte {
	length := intLength(key.P)
	length += intLength(key.Q)
	length += intLength(key.G)
	length += intLength(key.Y)

	ret := make([]byte, length)
	r := marshalInt(ret, key.P)
	r = marshalInt(r, key.Q)
	r = marshalInt(r, key.G)
	marshalInt(r, key.Y)

	return ret
}
