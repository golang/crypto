// Copyright 2019 ProtonTech AG.
//
// This file only tests EAX mode when instantiated with AES-128.

package eax

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/cipher"
	"encoding/hex"
	mathrand "math/rand"
	"testing"
)

const (
	blockLength = 16
	iterations  = 20
	maxLength   = 1 << 12
)

func TestEAXImplementsAEADInterface(t *testing.T) {
	var eaxInstance eax
	var aux interface{} = &eaxInstance
	_, ok := aux.(cipher.AEAD)
	if !ok {
		t.Errorf("Error: EAX does not implement AEAD interface")
	}
}

// Test vectors from https://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
func TestEncryptDecryptEAXTestVectors(t *testing.T) {
	for _, test := range testVectors {
		adata, _ := hex.DecodeString(test.header)
		key, _ := hex.DecodeString(test.key)
		nonce, _ := hex.DecodeString(test.nonce)
		targetPt, _ := hex.DecodeString(test.msg)
		targetCt, _ := hex.DecodeString(test.ciphertext)
		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		eax, errEax := NewEAX(aesCipher)
		if errEax != nil {
			panic(errEax)
		}

		ct := eax.Seal(nil, nonce, targetPt, adata)
		if !bytes.Equal(ct, targetCt) {
			t.Errorf(
				`Test vectors Encrypt error (ciphertexts don't match):
				Got:  %X
				Want: %X`, ct, targetCt)
		}
		pt, err := eax.Open(nil, nonce, ct, adata)
		if err != nil {
			t.Errorf(
				`Decrypt refused valid tag:
				ciphertext %X
				key %X
				nonce %X
				header %X`, ct, key, nonce, adata)
		}
		if !bytes.Equal(pt, targetPt) {
			t.Errorf(
				`Test vectors Decrypt error (plaintexts don't match):
				Got:  %X
				Want: %X`, pt, targetPt)
		}
	}
}

// Test vectors from generated file
func TestEncryptDecryptGoTestVectors(t *testing.T) {
	for _, test := range randomVectors {
		adata, _ := hex.DecodeString(test.header)
		key, _ := hex.DecodeString(test.key)
		nonce, _ := hex.DecodeString(test.nonce)
		targetPt, _ := hex.DecodeString(test.plaintext)
		targetCt, _ := hex.DecodeString(test.ciphertext)
		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		eax, errEax := NewEAX(aesCipher)
		if errEax != nil {
			panic(errEax)
		}

		ct := eax.Seal(nil, nonce, targetPt, adata)
		if !bytes.Equal(ct, targetCt) {
			t.Errorf(
				`Test vectors Encrypt error (ciphertexts don't match):
				Got:  %X
				Want: %X`, ct, targetCt)
		}
		pt, err := eax.Open(nil, nonce, ct, adata)
		if err != nil {
			t.Errorf(
				`Decrypt refused valid tag:
				ciphertext %X
				key %X
				nonce %X
				header %X`, ct, key, nonce, adata)
		}
		if !bytes.Equal(pt, targetPt) {
			t.Errorf(
				`Test vectors Decrypt error (plaintexts don't match):
				Got:  %X
				Want: %X`, pt, targetPt)
		}
	}
}

func TestNewEaxIncorrectNonceLength(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	e, errEax := NewEAXWithNonceAndTagSize(aesCipher, 0, 16)
	if errEax == nil || e != nil {
		t.Errorf("EAX with nonceLength 0 was not rejected")
	}
}

func TestSealIncorrectNonceLength(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	e, errEax := NewEAXWithNonceAndTagSize(aesCipher, 16, 16)
	if errEax != nil {
		panic(errEax)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Eax.Seal didn't panic on exceedingly long nonce")
		}
	}()
	longNonce := make([]byte, e.NonceSize() + 1)
	e.Seal(nil, longNonce, nil, nil)
}

func TestOpenIncorrectNonceLength(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	e, errEax := NewEAXWithNonceAndTagSize(aesCipher, 16, 16)
	if errEax != nil {
		panic(errEax)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Eax.Open didn't panic on exceedingly long nonce")
		}
	}()
	longNonce := make([]byte, e.NonceSize() + 1)
	_, err = e.Open(nil, longNonce, nil, nil)
	// Let the Open procedure panic
	if err != nil {}
}

func TestOpenShortCiphertext(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	e, errEax := NewEAXWithNonceAndTagSize(aesCipher, 16, 16)
	if errEax != nil {
		panic(errEax)
	}
	shortCt := make([]byte, e.Overhead()-1)
	pt, err := e.Open(nil, nil, nil, shortCt)
	if pt != nil || err == nil {
		t.Errorf("Eax.Open processed an exceedingly short ciphertext")
	}
}

// Generates random examples and tests correctness
func TestEncryptDecryptRandomVectorsWithPreviousData(t *testing.T) {
	// Considering AES
	allowedKeyLengths := []int{16, 24, 32}
	for _, keyLength := range allowedKeyLengths {
		for i := 0; i < iterations; i++ {
			pt := make([]byte, mathrand.Intn(maxLength))
			header := make([]byte, mathrand.Intn(maxLength))
			key := make([]byte, keyLength)
			nonce := make([]byte, 1+mathrand.Intn(blockLength))
			previousData := make([]byte, mathrand.Intn(maxLength-2*blockLength))
			// Populate items with crypto/rand
			itemsToRandomize := [][]byte{pt, header, key, nonce, previousData}
			for _, item := range itemsToRandomize {
				_, err := rand.Read(item)
				if err != nil {
					panic(err)
				}
			}
			aesCipher, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			eax, errEax := NewEAX(aesCipher)
			if errEax != nil {
				panic(errEax)
			}
			newData := eax.Seal(previousData, nonce, pt, header)
			ct := newData[len(previousData):]
			decrypted, err := eax.Open(nil, nonce, ct, header)
			if err != nil {
				t.Errorf(
					`Decrypt refused valid tag (not displaying long output)`)
					break
			}
			if !bytes.Equal(pt, decrypted) {
				t.Errorf(
					`Random Encrypt/Decrypt error (plaintexts don't match)`)
					break
			}
		}
	}
}

func TestRejectTamperedCiphertext(t *testing.T) {
	for i := 0; i < iterations; i++ {
		pt := make([]byte, mathrand.Intn(maxLength))
		header := make([]byte, mathrand.Intn(maxLength))
		key := make([]byte, blockLength)
		nonce := make([]byte, blockLength)
		itemsToRandomize := [][]byte{pt, header, key, nonce}
		for _, item := range itemsToRandomize {
			_, err := rand.Read(item)
			if err != nil {
				panic(err)
			}
		}
		aesCipher, errAes := aes.NewCipher(key)
		if errAes != nil {
			panic(errAes)
		}
		eax, errEax := NewEAX(aesCipher)
		if errEax != nil {
			panic(errEax)
		}
		ct := eax.Seal(nil, nonce, pt, header)
		// Change one byte of ct (could affect either the tag or the ciphertext)
		tampered := make([]byte, len(ct))
		copy(tampered, ct)
		for bytes.Equal(tampered, ct) {
			tampered[mathrand.Intn(len(ct))] = byte(mathrand.Intn(len(ct)))
		}
		_, err := eax.Open(nil, nonce, tampered, header)
		if err == nil {
			t.Errorf(`Tampered ciphertext was not refused decryption`)
			break
		}
	}
}

func TestParameters(t *testing.T) {
	t.Run("Should panic on unsupported keySize/blockSize", func(st *testing.T) {
		keySize := mathrand.Intn(32)
		for keySize == 16 {
			keySize = mathrand.Intn(32)
		}
		key := make([]byte, keySize)
		defer func() {
			if r := recover(); r == nil {
				st.Errorf("Eax didn't panic")
			}
		}()
		aesCipher, errAes := aes.NewCipher(key)
		if errAes != nil {
			panic(errAes)
		}
		_, errEax := NewEAX(aesCipher)
		// Don't panic here, let the New* procedure panic
		if errEax != nil { }
	})
	t.Run("Should return error on too long tagSize", func(st *testing.T) {
		tagSize := blockLength + 1 + mathrand.Intn(12)
		nonceSize := 1 + mathrand.Intn(16)
		key := make([]byte, blockLength)
		aesCipher, errAes := aes.NewCipher(key)
		if errAes != nil {
			panic(errAes)
		}
		_, err := NewEAXWithNonceAndTagSize(aesCipher, nonceSize, tagSize)
		if err == nil {
			st.Errorf("No error was given")
		}
	})
	t.Run("Should not give error with allowed custom parameters", func(st *testing.T) {
		key := make([]byte, blockLength)
		nonceSize := mathrand.Intn(32) + 1
		tagSize := 12 + mathrand.Intn(blockLength-11)
		aesCipher, errAes := aes.NewCipher(key)
		if errAes != nil {
			panic(errAes)
		}
		_, err := NewEAXWithNonceAndTagSize(aesCipher, nonceSize, tagSize)
		if err != nil {
			st.Errorf("An error was returned")
		}
	})
}

func BenchmarkEncrypt(b *testing.B) {
	headerLength := 16
	pt := make([]byte, maxLength)
	header := make([]byte, headerLength)
	key := make([]byte, blockLength)
	nonce := make([]byte, blockLength)
	itemsToRandomize := [][]byte{pt, header, key, nonce}
	for _, item := range itemsToRandomize {
		_, err := rand.Read(item)
		if err != nil {
			panic(err)
		}
	}
	aesCipher, errAes := aes.NewCipher(key)
	if errAes != nil {
		panic(errAes)
	}
	eax, errEax:= NewEAX(aesCipher)
	if errEax != nil {
		panic(errEax)
	}
	for i := 0; i < b.N; i++ {
		eax.Seal(nil, nonce, pt, header)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	headerLength := 16
	pt := make([]byte, maxLength)
	header := make([]byte, headerLength)
	key := make([]byte, blockLength)
	nonce := make([]byte, blockLength)
	itemsToRandomize := [][]byte{pt, header, key, nonce}
	for _, item := range itemsToRandomize {
		_, err := rand.Read(item)
		if err != nil {
			panic(err)
		}
	}
	aesCipher, errAes := aes.NewCipher(key)
	if errAes != nil {
		panic(errAes)
	}
	eax, errEax:= NewEAX(aesCipher)
	if errEax != nil {
		panic(errEax)
	}
	ct := eax.Seal(nil, nonce, pt, header)
	for i := 0; i < b.N; i++ {
		_, err := eax.Open(nil, nonce, ct, header)
		if err != nil {
			panic(err)
		}
	}
}
