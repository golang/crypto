package tokbind

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"

	"golang.org/x/crypto/cbs"
)

type TokenBindingKeyParameters uint8

const (
	rsa2048_pkcs1_5 TokenBindingKeyParameters = iota
	rsa2048_pss
	ecdsap256
	// (255)
)

type RSAPublicKey struct {
	Modulus        []byte //opaque modulus<1..2^16-1>;
	PublicExponent []byte //opaque publicexponent<1..2^8-1>;
}

func (pk *RSAPublicKey) marshal(bb *cbs.ByteBuilder) {
	bb.PutU16LengthPrefixed().Put(pk.Modulus)
	bb.Finish()
	bb.PutU8LengthPrefixed().Put(pk.PublicExponent)
	bb.Finish()
}

func (pk *RSAPublicKey) unmarshal(bs *cbs.ByteString) {
	pk.Modulus = bs.GetU16LengthPrefixed().Bytes()
	pk.PublicExponent = bs.GetU8LengthPrefixed().Bytes()
}

type ECPoint struct {
	Point []byte // opaque point <1..2^8-1>;
}

func (ecp *ECPoint) marshal(bb *cbs.ByteBuilder) {
	bb.PutU8LengthPrefixed().Put(ecp.Point)
	bb.Finish()
}

func (ecp *ECPoint) unmarshal(bs *cbs.ByteString) {
	ecp.Point = bs.GetU8LengthPrefixed().Bytes()
}

type TokenBindingID struct {
	KeyParameters TokenBindingKeyParameters
	//select (key_parameters) {
	//    case rsa2048_pkcs1.5:
	//    case rsa2048_pss:
	RSAPublicKey *RSAPublicKey
	//    case ecdsap256:
	ECPoint *ECPoint
	//} TokenBindingPublicKey;
}

func (tbid *TokenBindingID) marshal(bb *cbs.ByteBuilder) {
	bb.PutU8(uint(tbid.KeyParameters))
	child := bb.PutU16LengthPrefixed()
	switch tbid.KeyParameters {
	case rsa2048_pkcs1_5, rsa2048_pss:
		tbid.RSAPublicKey.marshal(child)
	case ecdsap256:
		tbid.ECPoint.marshal(child)
	default:
		panic("unkown")
	}
	bb.Finish()
}

func (tbid *TokenBindingID) unmarshal(bs *cbs.ByteString) {
	tbid.KeyParameters = TokenBindingKeyParameters(bs.GetU8())
	child := bs.GetU16LengthPrefixed()
	switch tbid.KeyParameters {
	case rsa2048_pkcs1_5, rsa2048_pss:
		tbid.RSAPublicKey = &RSAPublicKey{}
		tbid.RSAPublicKey.unmarshal(child)
	case ecdsap256:
		tbid.ECPoint = &ECPoint{}
		tbid.ECPoint.unmarshal(child)
	default:
		panic("unkown")
	}

}

type ExtensionType uint8

const (
	// There are currently no extension types defined.
	_ = iota
	// (255)
)

type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte //opaque extension_data<0..2^16-1>;
}

func (e *Extension) marshal(bb *cbs.ByteBuilder) {
	bb.PutU8(uint(e.ExtensionType))
	bb.PutU16LengthPrefixed().Put(e.ExtensionData)
	bb.Finish()
}

func (e *Extension) unmarshal(bs *cbs.ByteString) {
	e.ExtensionType = ExtensionType(bs.GetU8())
	e.ExtensionData = bs.GetU16LengthPrefixed().Bytes()
}

type TokenBindingType uint8

const (
	TokenBindingTypeProvided TokenBindingType = iota
	TokenBindingTypeReferred
)

type TokenBinding struct {
	TokenBindingType TokenBindingType
	TokenBindingID   TokenBindingID
	/* Signature over the concatenation
	   of tokenbinding_type,
	   key_parameters and exported
	   keying material (EKM) */
	Signature  []byte
	Extensions []Extension
}

func (tb *TokenBinding) marshal(bb *cbs.ByteBuilder) {
	bb.PutU8(uint(tb.TokenBindingType))
	tb.TokenBindingID.marshal(bb)
	bb.PutU16LengthPrefixed().Put(tb.Signature)
	bb.Finish()
	child := bb.PutU16LengthPrefixed()
	for _, e := range tb.Extensions {
		e.marshal(child)
	}
	child.Finish()
}

func (tb *TokenBinding) unmarshal(bs *cbs.ByteString) {
	tb.TokenBindingType = TokenBindingType(bs.GetU8())
	(&tb.TokenBindingID).unmarshal(bs)
	tb.Signature = bs.GetU16LengthPrefixed().Bytes()
	bs = bs.GetU16LengthPrefixed()
	for len(bs.Bytes()) > 0 {
		e := &Extension{}
		e.unmarshal(bs)
		tb.Extensions = append(tb.Extensions, *e)
	}
}

func (tb *TokenBinding) Verify(ekm []byte) bool {
	bb := cbs.NewByteBuilder()

	bb.PutU8(uint(tb.TokenBindingType))
	bb.PutU8(uint(tb.TokenBindingID.KeyParameters))
	bb.Put(ekm)

	digest := sha256.Sum256(bb.Bytes())

	switch tb.TokenBindingID.KeyParameters {
	case rsa2048_pkcs1_5, rsa2048_pss:
		pk := rsa.PublicKey{
			N: &big.Int{},
		}

		pk.N.SetBytes(tb.TokenBindingID.RSAPublicKey.Modulus)

		e := &big.Int{}
		e.SetBytes(tb.TokenBindingID.RSAPublicKey.PublicExponent)
		if e.IsInt64() {
			panic("public exponent too big")
		}
		pk.E = int(e.Int64())

		var err error
		switch tb.TokenBindingID.KeyParameters {
		case rsa2048_pkcs1_5:
			err = rsa.VerifyPKCS1v15(&pk, crypto.SHA256, digest[:], tb.Signature)
		case rsa2048_pss:
			err = rsa.VerifyPSS(&pk, crypto.SHA256, digest[:], tb.Signature, nil)
		}

		return err == nil
	case ecdsap256:
		pk := &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     &big.Int{},
			Y:     &big.Int{},
		}

		pointbs := cbs.NewByteString(tb.TokenBindingID.ECPoint.Point)
		pk.X.SetBytes(pointbs.Get(32).Bytes())
		pk.Y.SetBytes(pointbs.Get(32).Bytes())

		r := &big.Int{}
		s := &big.Int{}

		sigbs := cbs.NewByteString(tb.Signature)
		r.SetBytes(sigbs.Get(32).Bytes())
		s.SetBytes(sigbs.Get(32).Bytes())

		return ecdsa.Verify(pk, digest[:], r, s)
	}
	panic("here")
}

type TokenBindingMessage struct {
	TokenBindings []TokenBinding
}

func (tbm *TokenBindingMessage) marshal(bb *cbs.ByteBuilder) {
	child := bb.PutU16LengthPrefixed()
	for _, tb := range tbm.TokenBindings {
		tb.marshal(child)
	}
	bb.Finish()
}

func (tbm *TokenBindingMessage) unmarshal(bs *cbs.ByteString) {
	bs = bs.GetU16LengthPrefixed()
	for len(bs.Bytes()) > 0 {
		tb := &TokenBinding{}
		tb.unmarshal(bs)
		tbm.TokenBindings = append(tbm.TokenBindings, *tb)
	}
}
