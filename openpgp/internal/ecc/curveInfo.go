package ecc

import (
	"golang.org/x/crypto/openpgp/internal/encoding"
	"crypto/elliptic"
	"bytes"
	"golang.org/x/crypto/openpgp/ecdh"
	"golang.org/x/crypto/bitcurves"
	"golang.org/x/crypto/brainpool"
)
type SignatureAlgorithm uint8

const (
	ECDSA SignatureAlgorithm = 1
	EdDSA SignatureAlgorithm = 2
)
type curveInfo struct {
	Name string
	Oid *encoding.OID
	Curve elliptic.Curve
	SigAlgorithm SignatureAlgorithm
	CurveType ecdh.CurveType
}

var curves = []curveInfo {
	{
		Name: "NIST curve P-256",
		Oid: encoding.NewOID([]byte{0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}),
		Curve: elliptic.P256(),
		CurveType: ecdh.NISTCurve,
		SigAlgorithm: ECDSA,
	},
	{
		Name: "NIST curve P-384",
		Oid: encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x22}),
		Curve: elliptic.P384(),
		CurveType: ecdh.NISTCurve,
		SigAlgorithm: ECDSA,
	},
	{
		Name: "NIST curve P-521",
		Oid: encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x23}),
		Curve: elliptic.P521(),
		CurveType: ecdh.NISTCurve,
		SigAlgorithm: ECDSA,
	},
	{
		Name: "SecP256k1",
		Oid: encoding.NewOID([]byte{0x2B, 0x81, 0x04, 0x00, 0x0A}),
		Curve: bitcurves.S256(),
		CurveType: ecdh.BitCurve,
		SigAlgorithm: ECDSA,
	},
	{
		Name: "Curve25519",
		Oid: encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}),
		Curve: elliptic.P256(),// filler
		CurveType: ecdh.Curve25519,
		SigAlgorithm: ECDSA,
	},
	{
		Name: "Ed25519",
		Oid: encoding.NewOID([]byte{0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01}),
		Curve: elliptic.P256(), // filler
		CurveType: ecdh.NISTCurve,
		SigAlgorithm: EdDSA,
	},
	{
		Name: "Brainpool P256r1",
		Oid: encoding.NewOID([]byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07}),
		Curve: brainpool.P256r1(),
		CurveType: ecdh.BrainpoolCurve,
		SigAlgorithm: ECDSA,
	},
	{
		Name: "BrainpoolP384r1",
		Oid: encoding.NewOID([]byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B}),
		Curve: brainpool.P384r1(),
		CurveType: ecdh.BrainpoolCurve,
		SigAlgorithm: ECDSA,
	},
	{
		Name: "BrainpoolP512r1",
		Oid: encoding.NewOID([]byte{0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D}),
		Curve: brainpool.P512r1(),
		CurveType: ecdh.BrainpoolCurve,
		SigAlgorithm: ECDSA,
	},
}

func FindByCurve(curve elliptic.Curve) *curveInfo {
	for _, curveInfo := range curves {
		if curveInfo.Curve == curve {
			return &curveInfo
		}
	}
	return nil
}

func FindByOid(oid encoding.Field) *curveInfo {
	var rawBytes = oid.Bytes()
	for _, curveInfo := range curves {
		if bytes.Equal(curveInfo.Oid.Bytes(), rawBytes) {
			return &curveInfo
		}
	}
	return nil
}

func FindByName(name string) *curveInfo {
	for _, curveInfo := range curves {
		if curveInfo.Name == name {
			return &curveInfo
		}
	}
	return nil
}