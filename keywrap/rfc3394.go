// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package key wrap implements RFC 3394 and 5649
// for wrapping keys from key encrytion keys (kek).

package keywrap // import "golang.org/x/crypto/keywrap"

import (
	"crypto/aes"
	"errors"
)

var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

func aES(key, in []byte) ([]byte, error) {
	k, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	out := make([]byte, k.BlockSize())
	k.Encrypt(out, in)
	return out, nil
}

func aES1(key, in []byte) ([]byte, error) {
	k, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	out := make([]byte, k.BlockSize())
	k.Decrypt(out, in)
	return out, nil
}

// Unwrap key using kek as per rfc 3394.
func UnWrapKey(kek, ciphertext []byte) ([]byte, error) {

	if len(ciphertext)%8 != 0 {
		return nil, errors.New("invalid data length")
	}
	if len(ciphertext) < 16 {
		return nil, errors.New("invalid data length")
	}

	a := ciphertext[0:8]
	n := len(ciphertext)/8 - 1
	r := make([][8]byte, n+1)
	for i := 1; i <= n; i++ {
		copy(r[i][:], ciphertext[8*(i):8*(i+1)])
	}
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := (n * j) + i

			a[7] ^= uint8(t & 0xff)
			if t > 0xff {
				a[6] ^= byte((t >> 8) & 0xff)
				a[5] ^= byte((t >> 16) & 0xff)
				a[4] ^= byte((t >> 24) & 0xff)
			}

			b, e := aES1(kek, append(a, r[i][:]...))
			if e != nil {
				return nil, e
			}
			a = b[0:8]
			copy(r[i][:], b[8:16])
		}
	}
	tmp := a[:]
	for i := 1; i <= n; i++ {
		tmp = append(tmp, r[i][:]...)
	}
	return tmp, nil

}

// Wrap key using kek as per rfc 3394.
func WrapKey(kek, KEYData, iv []byte) ([]byte, error) {

	if len(KEYData)%8 != 0 {
		return nil, errors.New("invalid data length")
	}

	if iv == nil {
		iv = defaultIV
	}
	key := kek
	n := len(KEYData) / 8
	r := make([][8]byte, n+1)
	for i := 1; i <= n; i++ {
		copy(r[i][:], KEYData[8*(i-1):8*(i)])
	}
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			b, e := aES(key, append(iv[:], r[i][:]...))
			if e != nil {
				return nil, e
			}
			t := (n * j) + i
			iv = b[0:8]
			iv[7] = iv[7] ^ byte(t&0xff)

			if t > 0xff {
				iv[6] ^= byte((t >> 8) & 0xff)
				iv[5] ^= byte((t >> 16) & 0xff)
				iv[4] ^= byte((t >> 24) & 0xff)
			}
			copy(r[i][:], b[8:16])
		}
	}
	tmp := iv
	for i := 1; i <= n; i++ {
		tmp = append(tmp, r[i][:]...)
	}
	return tmp, nil
}

// Wrap key using kek as per rfc 5649.
func WrapKeyPadded(kek, kdata []byte) ([]byte, error) {
	n := len(kdata)
	if len(kdata)%8 != 0 {
		pad := make([]byte, 8-(len(kdata)%8))
		kdata = append(kdata, pad...)
	}
	IV := []byte{0xA6, 0x59, 0x59, 0xA6, 0x00, 0x00, 0x00, 0x00}
	//support 16 bit key size
	IV[7] |= byte(n & 0xff)
	IV[6] |= byte((n >> 8) & 0xff)
	IV[5] |= byte((n >> 16) & 0xff)
	IV[4] |= byte((n >> 24) & 0xff)

	if len(kdata) == 8 {
		return aES(kek, append(IV, kdata...))
	}
	return WrapKey(kek, kdata, IV)
}

// Unwrap key using KEK as per rfc 5649.
func UnwrapPadded(kek, ciphertext []byte) ([]byte, error) {
	var out []byte
	var e error
	n := len(ciphertext)
	if n == 16 {
		out, e = aES1(kek, ciphertext)
		if e != nil {
			return nil, e
		}
	} else {
		out, e = UnWrapKey(kek, ciphertext)
		if e != nil {
			return nil, e
		}
	}
	A := out[0:8]
	mli := int(A[7]) | (int(A[6]) << 8 & 0x0000ff00)
	b := out[8:n]
	return b[0:mli], nil
}
