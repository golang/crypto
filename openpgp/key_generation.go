// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"crypto"
	"math/big"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/openpgp/ecdh"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/internal/algorithm"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/rsa"
)

// NewEntity returns an Entity that contains a fresh RSA/RSA keypair with a
// single identity composed of the given full name, comment and email, any of
// which may be empty but must not contain any of "()<>\x00".
// If config is nil, sensible defaults will be used.
func NewEntity(name, comment, email string, config *packet.Config) (*Entity, error) {
	creationTime := config.Now()

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.InvalidArgumentError("user id field contained invalid characters")
	}

	// Generate a primary signing key
	primaryPrivRaw, err := newSigner(config)
	if err != nil {
		return nil, err
	}
	primary := packet.NewSignerPrivateKey(creationTime, primaryPrivRaw)

	isPrimaryId := true
	selfSignature := &packet.Signature{
		SigType:      packet.SigTypePositiveCert,
		PubKeyAlgo:   primary.PublicKey.PubKeyAlgo,
		Hash:         config.Hash(),
		CreationTime: creationTime,
		IssuerKeyId:  &primary.PublicKey.KeyId,
		IsPrimaryId:  &isPrimaryId,
		FlagsValid:   true,
		FlagSign:     true,
		FlagCertify:  true,
		MDC:          true, // true by default, see 5.8 vs. 5.14
		AEAD:         config.AEAD() != nil,
	}

	// Set the PreferredHash for the SelfSignature from the packet.Config.
	// If it is not the must-implement algorithm from rfc4880bis, append that.
	selfSignature.PreferredHash = []uint8{hashToHashId(config.Hash())}
	if config.Hash() != crypto.SHA256 {
		selfSignature.PreferredHash = append(selfSignature.PreferredHash, hashToHashId(crypto.SHA256))
	}

	// Likewise for DefaultCipher.
	selfSignature.PreferredSymmetric = []uint8{uint8(config.Cipher())}
	if config.Cipher() != packet.CipherAES128 {
		selfSignature.PreferredSymmetric = append(selfSignature.PreferredSymmetric, uint8(packet.CipherAES128))
	}

	// And for DefaultMode.
	selfSignature.PreferredAEAD = []uint8{uint8(config.AEAD().Mode())}
	if config.AEAD().Mode() != packet.AEADModeEAX {
		selfSignature.PreferredAEAD = append(selfSignature.PreferredAEAD, uint8(packet.AEADModeEAX))
	}

	// User ID binding signature
	err = selfSignature.SignUserId(uid.Id, &primary.PublicKey, primary, config)
	if err != nil {
		return nil, err
	}

	// Generate an encryption subkey
	subPrivRaw, err := newDecrypter(config)
	if err != nil {
		return nil, err
	}
	sub := packet.NewDecrypterPrivateKey(creationTime, subPrivRaw)
	sub.IsSubkey = true
	sub.PublicKey.IsSubkey = true

	subKey := Subkey{
		PublicKey:  &sub.PublicKey,
		PrivateKey: sub,
		Sig: &packet.Signature{
			CreationTime:              creationTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                primary.PublicKey.PubKeyAlgo,
			Hash:                      config.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &primary.PublicKey.KeyId,
		},
	}

	// Subkey binding signature
	err = subKey.Sig.SignKey(subKey.PublicKey, primary, config)
	if err != nil {
		return nil, err
	}

	return &Entity{
		PrimaryKey: &primary.PublicKey,
		PrivateKey: primary,
		Identities: map[string]*Identity{
			uid.Id: &Identity{
				Name:          uid.Id,
				UserId:        uid,
				SelfSignature: selfSignature,
				Signatures:    []*packet.Signature{selfSignature},
			},
		},
		Subkeys: []Subkey{subKey},
	}, nil
}

// AddSigningSubkey adds a signing keypair as a subkey to the Entity.
// If config is nil, sensible defaults will be used.
func (e *Entity) AddSigningSubkey(config *packet.Config) error {
	creationTime := config.Now()

	subPrivRaw, err := newSigner(config)
	if err != nil {
		return err
	}
	sub := packet.NewSignerPrivateKey(creationTime, subPrivRaw)

	subkey := Subkey{
		PublicKey:  &sub.PublicKey,
		PrivateKey: sub,
		Sig: &packet.Signature{
			CreationTime: creationTime,
			SigType:      packet.SigTypeSubkeyBinding,
			PubKeyAlgo:   e.PrimaryKey.PubKeyAlgo,
			Hash:         config.Hash(),
			FlagsValid:   true,
			FlagSign:     true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
			EmbeddedSignature: &packet.Signature{
				CreationTime: creationTime,
				SigType:      packet.SigTypePrimaryKeyBinding,
				PubKeyAlgo:   sub.PublicKey.PubKeyAlgo,
				Hash:         config.Hash(),
				IssuerKeyId:  &e.PrimaryKey.KeyId,
			},
		},
	}

	err = subkey.Sig.EmbeddedSignature.CrossSignKey(subkey.PublicKey, e.PrimaryKey, subkey.PrivateKey, config)
	if err != nil {
		return err
	}

	subkey.PublicKey.IsSubkey = true
	subkey.PrivateKey.IsSubkey = true
	if err = subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, config); err != nil {
		return err
	}

	e.Subkeys = append(e.Subkeys, subkey)
	return nil
}

// AddEncryptionSubkey adds an encryption keypair as a subkey to the Entity.
// If config is nil, sensible defaults will be used.
func (e *Entity) AddEncryptionSubkey(config *packet.Config) error {
	creationTime := config.Now()

	subPrivRaw, err := newDecrypter(config)
	if err != nil {
		return err
	}
	sub := packet.NewDecrypterPrivateKey(creationTime, subPrivRaw)

	subkey := Subkey{
		PublicKey:  &sub.PublicKey,
		PrivateKey: sub,
		Sig: &packet.Signature{
			CreationTime:              creationTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                e.PrimaryKey.PubKeyAlgo,
			Hash:                      config.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
		},
	}

	subkey.PublicKey.IsSubkey = true
	subkey.PrivateKey.IsSubkey = true
	if err = subkey.Sig.SignKey(subkey.PublicKey, e.PrivateKey, config); err != nil {
		return err
	}

	e.Subkeys = append(e.Subkeys, subkey)
	return nil
}

// Generates a signing key
func newSigner(config *packet.Config) (signer crypto.Signer, err error) {
	switch config.PublicKeyAlgorithm() {
	case packet.PubKeyAlgoRSA:
		bits := config.RSAModulusBits()
		var primaryPrimes []*big.Int
		if config != nil && len(config.RSAPrimes) >= 2 {
			primaryPrimes = config.RSAPrimes[0:2]
			config.RSAPrimes = config.RSAPrimes[2:]
		}
		return rsa.GenerateKeyWithPrimes(config.Random(), bits, primaryPrimes)
	case packet.PubKeyAlgoEdDSA:
		_, priv, err := ed25519.GenerateKey(config.Random())
		if err != nil {
			return nil, err
		}
		return &priv, nil
	default:
		return nil, errors.InvalidArgumentError("unsupported public key algorithm")
	}
}

// Generates an encryption/decryption key
func newDecrypter(config *packet.Config) (decrypter interface{}, err error) {
	switch config.PublicKeyAlgorithm() {
	case packet.PubKeyAlgoRSA:
		bits := config.RSAModulusBits()
		var primaryPrimes []*big.Int
		if config != nil && len(config.RSAPrimes) >= 2 {
			primaryPrimes = config.RSAPrimes[0:2]
			config.RSAPrimes = config.RSAPrimes[2:]
		}
		return rsa.GenerateKeyWithPrimes(config.Random(), bits, primaryPrimes)
	case packet.PubKeyAlgoEdDSA:
		fallthrough // When passing EdDSA, we generate an ECDH subkey
	case packet.PubKeyAlgoECDH:
		var kdf = ecdh.KDF{
			Hash:   algorithm.SHA512,
			Cipher: algorithm.AES256,
		}
		return ecdh.X25519GenerateKey(config.Random(), kdf)
	default:
		return nil, errors.InvalidArgumentError("unsupported public key algorithm")
	}
}
