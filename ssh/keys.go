// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
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
func parsePubKey(in []byte) (out interface{}, rest []byte, ok bool) {
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

// parseECDSA parses an ECDSA key according to RFC 5656, section 3.1.
func parseECDSA(in []byte) (out *ecdsa.PublicKey, rest []byte, ok bool) {
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
	return key, in, ok
}

// marshalPrivRSA serializes an RSA private key according to RFC 4253, section 6.6.
func marshalPrivRSA(priv *rsa.PrivateKey) []byte {
	e := new(big.Int).SetInt64(int64(priv.E))
	length := stringLength(len(KeyAlgoRSA))
	length += intLength(e)
	length += intLength(priv.N)

	ret := make([]byte, length)
	r := marshalString(ret, []byte(KeyAlgoRSA))
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
	r = marshalInt(r, key.Y)

	return ret
}

// marshalPubECDSA serializes an ECDSA public key according to RFC 5656, section 3.1.
func marshalPubECDSA(key *ecdsa.PublicKey) []byte {
	var identifier []byte
	switch key.Params().BitSize {
	case 256:
		identifier = []byte("nistp256")
	case 384:
		identifier = []byte("nistp384")
	case 521:
		identifier = []byte("nistp521")
	default:
		panic("ssh: unsupported ecdsa key size")
	}
	keyBytes := elliptic.Marshal(key.Curve, key.X, key.Y)

	length := stringLength(len(identifier))
	length += stringLength(len(keyBytes))

	ret := make([]byte, length)
	r := marshalString(ret, identifier)
	r = marshalString(r, keyBytes)
	return ret
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
func ParsePublicKey(in []byte) (out interface{}, rest []byte, ok bool) {
	return parsePubKey(in)
}

// MarshalAuthorizedKey returns a byte stream suitable for inclusion
// in an OpenSSH authorized_keys file following the format specified
// in the sshd(8) manual page.
func MarshalAuthorizedKey(key interface{}) []byte {
	b := &bytes.Buffer{}
	b.WriteString(algoName(key))
	b.WriteByte(' ')
	e := base64.NewEncoder(base64.StdEncoding, b)
	e.Write(serializePublickey(key))
	e.Close()
	b.WriteByte('\n')
	return b.Bytes()
}

// MarshalPublicKey serializes a supported key or certificate for use by the
// SSH wire protocol. It can be used for comparison with the pubkey argument
// of ServerConfig's PublicKeyCallback as well as for generating an
// authorized_keys or host_keys file.
func MarshalPublicKey(key interface{}) []byte {
	return serializePublickey(key)
}
