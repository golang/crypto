// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package openpgp

import (
	"math/big"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/openpgp/ecdh"
	"golang.org/x/crypto/openpgp/errors"
	"golang.org/x/crypto/openpgp/internal/algorithm"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/rsa"
)

const defaultRSAKeyBits = 2048

// NewEntity returns an Entity that contains a fresh RSA/RSA keypair with a
// single identity composed of the given full name, comment and email, any of
// which may be empty but must not contain any of "()<>\x00".
// If config is nil, sensible defaults will be used.
func NewEntity(name, comment, email string, config *packet.Config) (*Entity, error) {
	currentTime := config.Now()

	uid := packet.NewUserId(name, comment, email)
	if uid == nil {
		return nil, errors.InvalidArgumentError("user id field contained invalid characters")
	}

	var pubPrimary *packet.PublicKey
	var privPrimary *packet.PrivateKey

	var pubSubkey *packet.PublicKey
	var privSubkey *packet.PrivateKey

	var subkeyAlgorithm packet.PublicKeyAlgorithm

	if config.Algorithm == packet.PubKeyAlgoRSA {

		bits := defaultRSAKeyBits
		if config != nil && config.RSABits != 0 {
			bits = config.RSABits
		}

		var primaryPrimes []*big.Int
		if len(config.RSAPrimes) >= 2 {
			primaryPrimes = config.RSAPrimes[0:2]
		}

		primaryKey, err := rsa.GenerateKey(config.Random(), bits, primaryPrimes)
		if err != nil {
			return nil, err
		}

		privPrimary = packet.NewRSAPrivateKey(currentTime, primaryKey)
		pubPrimary = packet.NewRSAPublicKey(currentTime, &primaryKey.PublicKey)

		var subkeyPrimes []*big.Int
		if len(config.RSAPrimes) >= 4 {
			subkeyPrimes = config.RSAPrimes[2:4]
		}

		subkey, err := rsa.GenerateKey(config.Random(), bits, subkeyPrimes)
		if err != nil {
			return nil, err
		}

		pubSubkey = packet.NewRSAPublicKey(currentTime, &subkey.PublicKey)
		privSubkey = packet.NewRSAPrivateKey(currentTime, subkey)

		subkeyAlgorithm = packet.PubKeyAlgoRSA

	} else if config.Algorithm == packet.PubKeyAlgoEdDSA {

		pubPrimaryKey, primaryKey, err := ed25519.GenerateKey(config.Random())
		if err != nil {
			return nil, err
		}

		privPrimary = packet.NewEdDSAPrivateKey(currentTime, primaryKey)
		pubPrimary = packet.NewEdDSAPublicKey(currentTime, pubPrimaryKey)

		var kdf = ecdh.KDF{
			Hash:   algorithm.SHA512,
			Cipher: algorithm.AES256,
		}

		privSubkeyRaw, err := ecdh.X25519GenerateKey(config.Random(), kdf)
		if err != nil {
			return nil, err
		}

		pubSubkey = packet.NewECDHPublicKey(currentTime, &privSubkeyRaw.PublicKey)
		privSubkey = packet.NewECDHPrivateKey(currentTime, privSubkeyRaw)

		subkeyAlgorithm = packet.PubKeyAlgoEdDSA

	} else {
		return nil, errors.InvalidArgumentError("unsupported public key algorithm")
	}

	e := &Entity{
		PrimaryKey: pubPrimary,
		PrivateKey: privPrimary,
		Identities: make(map[string]*Identity),
	}
	isPrimaryId := true
	e.Identities[uid.Id] = &Identity{
		Name:   uid.Id,
		UserId: uid,
		SelfSignature: &packet.Signature{
			CreationTime: currentTime,
			SigType:      packet.SigTypePositiveCert,
			PubKeyAlgo:   config.Algorithm,
			Hash:         config.Hash(),
			IsPrimaryId:  &isPrimaryId,
			FlagsValid:   true,
			FlagSign:     true,
			FlagCertify:  true,
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		},
	}

	// If the user passes in a DefaultHash via packet.Config,
	// set the PreferredHash for the SelfSignature.
	if config != nil && config.DefaultHash != 0 {
		e.Identities[uid.Id].SelfSignature.PreferredHash = []uint8{hashToHashId(config.DefaultHash)}
	}

	// Likewise for DefaultCipher.
	if config != nil && config.DefaultCipher != 0 {
		e.Identities[uid.Id].SelfSignature.PreferredSymmetric = []uint8{uint8(config.DefaultCipher)}
	}

	e.Subkeys = make([]Subkey, 1)
	e.Subkeys[0] = Subkey{
		PublicKey:  pubSubkey,
		PrivateKey: privSubkey,
		Sig: &packet.Signature{
			CreationTime:              currentTime,
			SigType:                   packet.SigTypeSubkeyBinding,
			PubKeyAlgo:                subkeyAlgorithm,
			Hash:                      config.Hash(),
			FlagsValid:                true,
			FlagEncryptStorage:        true,
			FlagEncryptCommunications: true,
			IssuerKeyId:               &e.PrimaryKey.KeyId,
		},
	}
	e.Subkeys[0].PublicKey.IsSubkey = true
	e.Subkeys[0].PrivateKey.IsSubkey = true

	return e, nil
}
