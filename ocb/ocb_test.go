// Copyright 2019 ProtonTech AG.

package ocb

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	mathrand "math/rand"
	"testing"
	"time"
)

const (
	blockLength = 16
	iterations  = 20
	maxLength   = 1 << 12
)

func TestOCBImplementsAEADInterface(t *testing.T) {
	var ocbInstance ocb
	var aux interface{} = &ocbInstance
	_, ok := aux.(cipher.AEAD)
	if !ok {
		t.Errorf("Error: OCB can't implement AEAD interface")
	}
}

func TestZeroHash(t *testing.T) {
	// Key is shared by all test vectors
	aesCipher, err := aes.NewCipher(testKey)
	if err != nil {
		panic(err)
	}
	o := ocb{
		block:     aesCipher,
		tagSize:   defaultTagSize,
		nonceSize: defaultNonceSize,
	}

	blockSize := o.block.BlockSize()
	if !bytes.Equal(o.hash(make([]byte, 0)), make([]byte, blockSize)) {
		t.Errorf("Error: Hash() did not return a correct amount of zero bytes")
	}
}

func TestNewOCBIncorrectNonceLength(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	e, errOcb := NewOCBWithNonceAndTagSize(aesCipher, 0, 16)
	if errOcb == nil || e != nil {
		t.Errorf("OCB with nonceLength 0 was not rejected")
	}
}

func TestSealIncorrectNonceLength(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	o, errOcb := NewOCBWithNonceAndTagSize(aesCipher, 15, 16)
	if errOcb != nil {
		panic(errOcb)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Ocb.Seal didn't panic on exceedingly long nonce")
		}
	}()
	longNonce := make([]byte, o.NonceSize() + 1)
	o.Seal(nil, longNonce, nil, nil)
}

func TestOpenIncorrectNonceLength(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	o, errOcb := NewOCBWithNonceAndTagSize(aesCipher, 15, 16)
	if errOcb != nil {
		panic(errOcb)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Ocb.Open didn't panic on exceedingly long nonce")
		}
	}()
	longNonce := make([]byte, o.NonceSize() + 1)
	_, err = o.Open(nil, longNonce, nil, nil)
	// Let the Open procedure panic
	if err != nil {}
}

func TestOpenShortCiphertext(t *testing.T) {
	aesCipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		panic(err)
	}
	o, errOcb := NewOCBWithNonceAndTagSize(aesCipher, 15, 16)
	if errOcb != nil {
		panic(errOcb)
	}
	shortCt := make([]byte, o.Overhead()-1)
	pt, err := o.Open(nil, nil, nil, shortCt)
	if pt != nil || err == nil {
		t.Errorf("Ocb.Open processed an exceedingly short ciphertext")
	}
}

func TestEncryptDecryptRFC7253TestVectors(t *testing.T) {
	// Key is shared by all test vectors
	aesCipher, err := aes.NewCipher(testKey)
	if err != nil {
		panic(err)
	}
	ocbInstance, errO := NewOCB(aesCipher)
	if errO != nil {
		panic(errO)
	}
	for _, test := range rfc7253testVectors {
		nonce, _ := hex.DecodeString(test.nonce)
		adata, _ := hex.DecodeString(test.header)
		targetPt, _ := hex.DecodeString(test.plaintext)
		targetCt, _ := hex.DecodeString(test.ciphertext)
		ct := ocbInstance.Seal(nil, nonce, targetPt, adata)
		// Encrypt
		if !bytes.Equal(ct, targetCt) {
			t.Errorf(
				`RFC7253 Test vectors Encrypt error (ciphertexts don't match):
			Got:
			%X
			Want:
			%X`, ct, targetCt)
		}
		// Decrypt
		pt, err := ocbInstance.Open(nil, nonce, targetCt, adata)
		if err != nil {
			t.Errorf(
				`RFC7253 Valid ciphertext was refused decryption:
				plaintext %X
				nonce %X
				header %X
				ciphertext %X`, targetPt, nonce, adata, targetCt)
		}
		if !bytes.Equal(pt, targetPt) {
			t.Errorf(
				`RFC7253 test vectors Decrypt error (plaintexts don't match):
			Got:
			%X
			Want:
			%X`, pt, targetPt)
		}
	}
}

func TestEncryptDecryptRFC7253TagLen96(t *testing.T) {
	test := rfc7253TestVectorTaglen96
	key, _ := hex.DecodeString(test.key)
	nonce, _ := hex.DecodeString(test.nonce)
	adata, _ := hex.DecodeString(test.header)
	targetPt, _ := hex.DecodeString(test.plaintext)
	targetCt, _ := hex.DecodeString(test.ciphertext)
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ocbInstance, errO := NewOCBWithNonceAndTagSize(aesCipher, len(nonce), 96/8)
	if errO != nil {
		panic(errO)
	}
	ct := ocbInstance.Seal(nil, nonce, targetPt, adata)
	if !bytes.Equal(ct, targetCt) {
		t.Errorf(
			`RFC7253 test tagLen96 error (ciphertexts don't match):
		Got:
		%X
		Want:
		%X`, ct, targetCt)
	}
	pt, err := ocbInstance.Open(nil, nonce, targetCt, adata)
	if err != nil {
		t.Errorf(`RFC7253 test tagLen96 was refused decryption`)
	}
	if !bytes.Equal(pt, targetPt) {
		t.Errorf(
			`RFC7253 test tagLen96 error (plaintexts don't match):
		Got:
		%X
		Want:
		%X`, pt, targetPt)
	}
}

// This test algorithm is defined in RFC7253, Appendix A
func TestEncryptDecryptRFC7253DifferentKeySizes(t *testing.T) {
	for _, testCase := range rfc7253AlgorithmTest {
		keyLen := testCase.KEYLEN
		tagLen := testCase.TAGLEN
		key := make([]byte, keyLen/8)
		key[len(key)-1] = byte(tagLen)

		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ocbInstance, err := NewOCBWithNonceAndTagSize(aesCipher, 12, tagLen/8)
		if err != nil {
			panic(err)
		}
		C := make([]byte, 0)
		ending := make([]byte, 4)
		var N, S []byte
		for i := 0; i < 128; i++ {
			S = make([]byte, i)
			binary.BigEndian.PutUint32(ending, uint32(3*i+1))
			N = append(make([]byte, 8), ending...)
			// C ||= ENC(S, N, S)
			C = append(C, ocbInstance.Seal(nil, N, S, S)...)
			binary.BigEndian.PutUint32(ending, uint32(3*i+2))
			N = append(make([]byte, 8), ending...)
			// C ||= ENC(S, N, <empty>)
			C = append(C, ocbInstance.Seal(nil, N, S, make([]byte, 0))...)
			binary.BigEndian.PutUint32(ending, uint32(3*i+3))
			N = append(make([]byte, 8), ending...)
			// C ||= ENC(<empty>, N, S)
			C = append(C, ocbInstance.Seal(nil, N, make([]byte, 0), S)...)
		}
		binary.BigEndian.PutUint32(ending, uint32(385))
		N = append(make([]byte, 8), ending...)
		// output = Enc(<empty>, N, C)
		output := ocbInstance.Seal(nil, N, make([]byte, 0), C)
		targetOutput, _ := hex.DecodeString(testCase.OUTPUT)
		if !bytes.Equal(output, targetOutput) {
			t.Errorf(
				`RFC7253 Test algorithm error (outputs do not match):
		AES_%d_OCB_TAGLEN%d
		Got:
		%X
		Want:
		%X`, keyLen, tagLen, output, targetOutput)
		}
	}
}

func TestEncryptDecryptGoTestVectors(t *testing.T) {
	for _, test := range randomVectors {
		key, _ := hex.DecodeString(test.key)
		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		nonce, _ := hex.DecodeString(test.nonce)
		adata, _ := hex.DecodeString(test.header)
		targetPt, _ := hex.DecodeString(test.plaintext)
		targetCt, _ := hex.DecodeString(test.ciphertext)
		tagSize := len(targetCt) - len(targetPt)
		ocbInstance, errO := NewOCBWithNonceAndTagSize(aesCipher, len(nonce), tagSize)
		if errO != nil {
			panic(errO)
		}
		// Encrypt
		ct := ocbInstance.Seal(nil, nonce, targetPt, adata)
		if !bytes.Equal(ct, targetCt) {
			t.Errorf(
				`Go Test vectors Encrypt error (ciphertexts don't match):
			Got:
			%X
			Want:
			%X`, ct, targetCt)
		}

		// Decrypt
		pt, err := ocbInstance.Open(nil, nonce, targetCt, adata)
		if err != nil {
			t.Errorf(
				`Valid Go ciphertext was refused decryption:
			plaintext %X
			nonce %X
			header %X
			ciphertext %X`, targetPt, nonce, adata, targetCt)
		}
		if !bytes.Equal(pt, targetPt) {
			t.Errorf(
				`Go Test vectors Decrypt error (plaintexts don't match):
			Got:
			%X
			Want:
			%X`, pt, targetPt)
		}
	}
}

func TestEncryptDecryptRandVectorsWithPreviousData(t *testing.T) {
	mathrand.Seed(time.Now().UnixNano())
	allowedKeyLengths := []int{16, 24, 32}
	for _, keyLength := range allowedKeyLengths {
		for i := 0; i < iterations; i++ {
			pt := make([]byte, mathrand.Intn(maxLength))
			header := make([]byte, mathrand.Intn(maxLength))
			key := make([]byte, keyLength)
			// Testing for short nonces but take notice they are not recommended
			nonce := make([]byte, 1+mathrand.Intn(blockLength-1))
			previousData := make([]byte, mathrand.Intn(maxLength))
			// Populate items with crypto/rand
			itemsToPopulate := [][]byte{pt, header, key, nonce, previousData}
			for _, item := range itemsToPopulate {
				_, err := rand.Read(item)
				if err != nil {
				}
			}
			aesCipher, err := aes.NewCipher(key)
			if err != nil {
				panic(err)
			}
			ocb, errO := NewOCB(aesCipher)
			if errO != nil {
				panic(errO)
			}
			newData := ocb.Seal(previousData, nonce, pt, header)
			ct := newData[len(previousData):]
			decrypted, err := ocb.Open(nil, nonce, ct, header)
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
		// Note: Nonce cannot equal blockLength
		nonce := make([]byte, blockLength-1)
		itemsToPopulate := [][]byte{pt, header, key, nonce}
		for _, item := range itemsToPopulate {
			_, err := rand.Read(item)
			if err != nil {
			}
		}
		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			panic(err)
		}
		ocb, errO := NewOCB(aesCipher)
		if errO != nil {
			panic(errO)
		}
		ct := ocb.Seal(nil, nonce, pt, header)
		// Change one byte of ct (could affect either the tag or the ciphertext)
		tampered := make([]byte, len(ct))
		copy(tampered, ct)
		for bytes.Equal(tampered, ct) {
			tampered[mathrand.Intn(len(ct))] = byte(mathrand.Intn(len(ct)))
		}
		_, err = ocb.Open(nil, nonce, tampered, header)
		if err == nil {
			t.Errorf(
				"Tampered ciphertext was not refused decryption (OCB did not return an error)")
			return
		}
	}
}

func TestParameters(t *testing.T) {
	blockLength := 16
	key := make([]byte, blockLength)
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	t.Run("Should return error on too long tagSize", func(st *testing.T) {
		tagSize := blockLength + 1 + mathrand.Intn(12)
		nonceSize := 1 + mathrand.Intn(16)
		_, err := NewOCBWithNonceAndTagSize(aesCipher, nonceSize, tagSize)
		if err == nil {
			st.Errorf("No error was returned")
		}
	})
	t.Run("Should return error on too long nonceSize", func(st *testing.T) {
		tagSize := 12
		nonceSize := blockLength + mathrand.Intn(16)
		_, err := NewOCBWithNonceAndTagSize(aesCipher, nonceSize, tagSize)
		if err == nil {
			st.Errorf("No error was returned")
		}
	})
	t.Run(
		"Should not give error with allowed parameters", func(st *testing.T) {
			// Noncesize ∈  12,...,blocklength - 1
			// Shorter values of nonceSize are not recommended.
			nonceSize := 12 + mathrand.Intn(blockLength-12)
			tagSize := 12 + mathrand.Intn(blockLength-11)
			_, err := NewOCBWithNonceAndTagSize(aesCipher, nonceSize, tagSize)
			if err != nil {
				st.Errorf("An error was returned")
			}
		})
}

func BenchmarkEncrypt(b *testing.B) {
	plaintextLength := maxLength
	headerLength := 16
	pt := make([]byte, plaintextLength)
	header := make([]byte, headerLength)
	key := make([]byte, blockLength)
	nonce := make([]byte, blockLength-1)
	itemsToPopulate := [][]byte{pt, header, key, nonce}
	for _, item := range itemsToPopulate {
		_, err := rand.Read(item)
		if err != nil {
		}
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ocb, errO := NewOCB(aesCipher)
	if errO != nil {
		panic(errO)
	}
	for i := 0; i < b.N; i++ {
		ocb.Seal(nil, nonce, pt, header)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	plaintextLength := maxLength
	headerLength := 16
	pt := make([]byte, plaintextLength)
	header := make([]byte, headerLength)
	key := make([]byte, blockLength)
	nonce := make([]byte, blockLength-1)
	itemsToPopulate := [][]byte{pt, header, key, nonce}
	for _, item := range itemsToPopulate {
		_, err := rand.Read(item)
		if err != nil {
		}
	}
	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ocb, errO := NewOCB(aesCipher)
	if errO != nil {
		panic(errO)
	}
	ct := ocb.Seal(nil, nonce, pt, header)
	for i := 0; i < b.N; i++ {
		_, err := ocb.Open(nil, nonce, ct, header)
		if err != nil {
			panic(err)
		}
	}
}
