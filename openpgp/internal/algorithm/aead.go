// Copyright (C) 2019 ProtonTech AG

package algorithm

import (
	"crypto/cipher"
	"golang.org/x/crypto/eax"
	"golang.org/x/crypto/ocb"
)

// AEADMode defines the Authenticated Encryption with Associated Data mode of
// operation.
type AEADMode uint8

// Supported modes of operation (see RFC4880bis [EAX] and RFC7253)
const (
	AEADModeEAX = AEADMode(1)
	AEADModeOCB = AEADMode(2)
	AEADModeGCM = AEADMode(100)
)

// TagLength returns the length in bytes of authentication tags.
func (mode AEADMode) TagLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 16
	case AEADModeGCM:
		return 16
	}
	panic("Unsupported AEAD mode")
}

// NonceLength returns the length in bytes of nonces.
func (mode AEADMode) NonceLength() int {
	switch mode {
	case AEADModeEAX:
		return 16
	case AEADModeOCB:
		return 15
	case AEADModeGCM:
		return 12
	}
	panic("unsupported aead mode")
}

// New returns a fresh instance of the given mode
func (mode AEADMode) New(block cipher.Block) (alg cipher.AEAD) {
	var err error
	switch mode {
	case AEADModeEAX:
		alg, err = eax.NewEAX(block)
	case AEADModeOCB:
		alg, err = ocb.NewOCB(block)
	case AEADModeGCM:
		alg, err = cipher.NewGCM(block)
	}
	if err != nil {
		panic(err.Error())
	}
	return alg
}
