// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
)

// These constants represent the algorithm names for key types supported by this
// package.
const (
	KeyAlgoRSA      = "ssh-rsa"
	KeyAlgoDSA      = "ssh-dss"
	KeyAlgoECDSA256 = "ecdsa-sha2-nistp256"
	KeyAlgoECDSA384 = "ecdsa-sha2-nistp384"
	KeyAlgoECDSA521 = "ecdsa-sha2-nistp521"
)

// parsePubKey parses a public key according to RFC 4253, section 6.6.
func parsePubKey(in []byte) (pubKey PublicKey, rest []byte, ok bool) {
	algo, in, ok := parseString(in)
	if !ok {
		return
	}

	switch string(algo) {
	case KeyAlgoRSA:
		return parseRSA(in)
	case KeyAlgoDSA:
		return parseDSA(in)
	case KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521:
		return parseECDSA(in)
	case CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01:
		return parseOpenSSHCertV01(in, string(algo))
	}
	return nil, nil, false
}

// parseAuthorizedKey parses a public key in OpenSSH authorized_keys format
// (see sshd(8) manual page) once the options and key type fields have been
// removed.
func parseAuthorizedKey(in []byte) (out interface{}, comment string, ok bool) {
	in = bytes.TrimSpace(in)

	i := bytes.IndexAny(in, " \t")
	if i == -1 {
		i = len(in)
	}
	base64Key := in[:i]

	key := make([]byte, base64.StdEncoding.DecodedLen(len(base64Key)))
	n, err := base64.StdEncoding.Decode(key, base64Key)
	if err != nil {
		return
	}
	key = key[:n]
	out, _, ok = parsePubKey(key)
	if !ok {
		return nil, "", false
	}
	comment = string(bytes.TrimSpace(in[i:]))
	return
}

// ParseAuthorizedKeys parses a public key from an authorized_keys
// file used in OpenSSH according to the sshd(8) manual page.
func ParseAuthorizedKey(in []byte) (out interface{}, comment string, options []string, rest []byte, ok bool) {
	for len(in) > 0 {
		end := bytes.IndexByte(in, '\n')
		if end != -1 {
			rest = in[end+1:]
			in = in[:end]
		} else {
			rest = nil
		}

		end = bytes.IndexByte(in, '\r')
		if end != -1 {
			in = in[:end]
		}

		in = bytes.TrimSpace(in)
		if len(in) == 0 || in[0] == '#' {
			in = rest
			continue
		}

		i := bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		field := string(in[:i])
		switch field {
		case KeyAlgoRSA, KeyAlgoDSA:
			out, comment, ok = parseAuthorizedKey(in[i:])
			if ok {
				return
			}
		case KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521:
			// We don't support these keys.
			in = rest
			continue
		case CertAlgoRSAv01, CertAlgoDSAv01,
			CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01:
			// We don't support these certificates.
			in = rest
			continue
		}

		// No key type recognised. Maybe there's an options field at
		// the beginning.
		var b byte
		inQuote := false
		var candidateOptions []string
		optionStart := 0
		for i, b = range in {
			isEnd := !inQuote && (b == ' ' || b == '\t')
			if (b == ',' && !inQuote) || isEnd {
				if i-optionStart > 0 {
					candidateOptions = append(candidateOptions, string(in[optionStart:i]))
				}
				optionStart = i + 1
			}
			if isEnd {
				break
			}
			if b == '"' && (i == 0 || (i > 0 && in[i-1] != '\\')) {
				inQuote = !inQuote
			}
		}
		for i < len(in) && (in[i] == ' ' || in[i] == '\t') {
			i++
		}
		if i == len(in) {
			// Invalid line: unmatched quote
			in = rest
			continue
		}

		in = in[i:]
		i = bytes.IndexAny(in, " \t")
		if i == -1 {
			in = rest
			continue
		}

		field = string(in[:i])
		switch field {
		case KeyAlgoRSA, KeyAlgoDSA:
			out, comment, ok = parseAuthorizedKey(in[i:])
			if ok {
				options = candidateOptions
				return
			}
		}

		in = rest
		continue
	}

	return
}

// ParsePublicKey parses an SSH public key formatted for use in
// the SSH wire protocol.
func ParsePublicKey(in []byte) (out PublicKey, rest []byte, ok bool) {
	return parsePubKey(in)
}

// MarshalAuthorizedKey returns a byte stream suitable for inclusion
// in an OpenSSH authorized_keys file following the format specified
// in the sshd(8) manual page.
func MarshalAuthorizedKey(key PublicKey) []byte {
	b := &bytes.Buffer{}
	b.WriteString(key.PublicKeyAlgo())
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(MarshalPublicKey(key))
	e.Close()
	b.WriteByte('\n')
	return b.Bytes()
}

// PublicKey is an abstraction of different types of public keys.
type PublicKey interface {
	// PrivateKeyAlgo returns the name of the encryption system.
	PrivateKeyAlgo() string

	// PublicKeyAlgo returns the algorithm for the public key,
	// which may be different from PrivateKeyAlgo for certificates.
	PublicKeyAlgo() string

	// Marshal returns the serialized key data in SSH wire format,
	// without the name prefix.  Callers should typically use
	// MarshalPublicKey().
	Marshal() []byte

	// Verify that sig is a signature on the given data using this
	// key. This function will hash the data appropriately first.
	Verify(data []byte, sigBlob []byte) bool

	// RawKey returns the underlying object, eg. *rsa.PublicKey.
	RawKey() interface{}
}

// TODO(hanwen): define PrivateKey too.

type rsaPublicKey rsa.PublicKey

func (r *rsaPublicKey) PrivateKeyAlgo() string {
	return "ssh-rsa"
}

func (r *rsaPublicKey) PublicKeyAlgo() string {
	return "ssh-rsa"
}

func (r *rsaPublicKey) RawKey() interface{} {
	return (*rsa.PublicKey)(r)
}

// parseRSA parses an RSA key according to RFC 4253, section 6.6.
func parseRSA(in []byte) (out PublicKey, rest []byte, ok bool) {
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
	return NewRSAPublicKey(key), in, ok
}

func (r *rsaPublicKey) Marshal() []byte {
	// See RFC 4253, section 6.6.
	e := new(big.Int).SetInt64(int64(r.E))
	length := intLength(e)
	length += intLength(r.N)

	ret := make([]byte, length)
	rest := marshalInt(ret, e)
	marshalInt(rest, r.N)

	return ret
}

func (r *rsaPublicKey) Verify(data []byte, sig []byte) bool {
	h := crypto.SHA1.New()
	h.Write(data)
	digest := h.Sum(nil)
	return rsa.VerifyPKCS1v15((*rsa.PublicKey)(r), crypto.SHA1, digest, sig) == nil
}

func NewRSAPublicKey(k *rsa.PublicKey) PublicKey {
	return (*rsaPublicKey)(k)
}

type dsaPublicKey dsa.PublicKey

func (r *dsaPublicKey) PrivateKeyAlgo() string {
	return "ssh-dss"
}
func (r *dsaPublicKey) PublicKeyAlgo() string {
	return "ssh-dss"
}
func (r *dsaPublicKey) RawKey() interface{} {
	return (*dsa.PublicKey)(r)
}

// parseDSA parses an DSA key according to RFC 4253, section 6.6.
func parseDSA(in []byte) (out PublicKey, rest []byte, ok bool) {
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
	return NewDSAPublicKey(key), in, ok
}

func (r *dsaPublicKey) Marshal() []byte {
	// See RFC 4253, section 6.6.
	length := intLength(r.P)
	length += intLength(r.Q)
	length += intLength(r.G)
	length += intLength(r.Y)

	ret := make([]byte, length)
	rest := marshalInt(ret, r.P)
	rest = marshalInt(rest, r.Q)
	rest = marshalInt(rest, r.G)
	marshalInt(rest, r.Y)

	return ret
}

func (k *dsaPublicKey) Verify(data []byte, sigBlob []byte) bool {
	h := crypto.SHA1.New()
	h.Write(data)
	digest := h.Sum(nil)

	// Per RFC 4253, section 6.6,
	// The value for 'dss_signature_blob' is encoded as a string containing
	// r, followed by s (which are 160-bit integers, without lengths or
	// padding, unsigned, and in network byte order).
	// For DSS purposes, sig.Blob should be exactly 40 bytes in length.
	if len(sigBlob) != 40 {
		return false
	}
	r := new(big.Int).SetBytes(sigBlob[:20])
	s := new(big.Int).SetBytes(sigBlob[20:])
	return dsa.Verify((*dsa.PublicKey)(k), digest, r, s)
}

func NewDSAPublicKey(k *dsa.PublicKey) PublicKey {
	return (*dsaPublicKey)(k)
}

type ecdsaPublicKey ecdsa.PublicKey

func NewECDSAPublicKey(k *ecdsa.PublicKey) PublicKey {
	return (*ecdsaPublicKey)(k)
}
func (r *ecdsaPublicKey) RawKey() interface{} {
	return (*ecdsa.PublicKey)(r)
}

func (key *ecdsaPublicKey) PrivateKeyAlgo() string {
	return "ecdh-sha2-" + key.nistID()
}

func (key *ecdsaPublicKey) nistID() string {
	switch key.Params().BitSize {
	case 256:
		return "nistp256"
	case 384:
		return "nistp384"
	case 521:
		return "nistp521"
	}
	panic("ssh: unsupported ecdsa key size")
}

// RFC 5656, section 6.2.1 (for ECDSA).
func (key *ecdsaPublicKey) hash() crypto.Hash {
	switch key.Params().BitSize {
	case 256:
		return crypto.SHA256
	case 384:
		return crypto.SHA384
	case 521:
		return crypto.SHA512
	}
	panic("ssh: unsupported ecdsa key size")
}

func (key *ecdsaPublicKey) PublicKeyAlgo() string {
	switch key.Params().BitSize {
	case 256:
		return KeyAlgoECDSA256
	case 384:
		return KeyAlgoECDSA384
	case 521:
		return KeyAlgoECDSA521
	}
	panic("ssh: unsupported ecdsa key size")
}

// parseECDSA parses an ECDSA key according to RFC 5656, section 3.1.
func parseECDSA(in []byte) (out PublicKey, rest []byte, ok bool) {
	var identifier []byte
	if identifier, in, ok = parseString(in); !ok {
		return
	}

	key := new(ecdsa.PublicKey)

	switch string(identifier) {
	case "nistp256":
		key.Curve = elliptic.P256()
	case "nistp384":
		key.Curve = elliptic.P384()
	case "nistp521":
		key.Curve = elliptic.P521()
	default:
		ok = false
		return
	}

	var keyBytes []byte
	if keyBytes, in, ok = parseString(in); !ok {
		return
	}

	key.X, key.Y = elliptic.Unmarshal(key.Curve, keyBytes)
	if key.X == nil || key.Y == nil {
		ok = false
		return
	}
	return NewECDSAPublicKey(key), in, ok
}

func (key *ecdsaPublicKey) Marshal() []byte {
	// See RFC 5656, section 3.1.
	keyBytes := elliptic.Marshal(key.Curve, key.X, key.Y)

	ID := key.nistID()
	length := stringLength(len(ID))
	length += stringLength(len(keyBytes))

	ret := make([]byte, length)
	r := marshalString(ret, []byte(ID))
	r = marshalString(r, keyBytes)
	return ret
}

func (key *ecdsaPublicKey) Verify(data []byte, sigBlob []byte) bool {
	h := key.hash().New()
	h.Write(data)
	digest := h.Sum(nil)

	// Per RFC 5656, section 3.1.2,
	// The ecdsa_signature_blob value has the following specific encoding:
	//    mpint    r
	//    mpint    s
	r, rest, ok := parseInt(sigBlob)
	if !ok {
		return false
	}
	s, rest, ok := parseInt(rest)
	if !ok || len(rest) > 0 {
		return false
	}
	return ecdsa.Verify((*ecdsa.PublicKey)(key), digest, r, s)
}
