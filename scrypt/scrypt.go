// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package scrypt implements the scrypt key derivation function as defined in
// Colin Percival's paper "Stronger Key Derivation via Sequential Memory-Hard
// Functions" (http://www.tarsnap.com/scrypt/scrypt.pdf).
package scrypt

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"code.google.com/p/go.crypto/pbkdf2"
	"code.google.com/p/go.crypto/salsa20/salsa"
)

const maxInt = int(^uint(0) >> 1)

// blockCopy copies n bytes from src into dst.
func blockCopy(dst, src []byte, n int) {
	copy(dst, src[:n])
}

// blockXOR XORs bytes from dst with n bytes from src.
func blockXOR(dst, src []byte, n int) {
	for i, v := range src[:n] {
		dst[i] ^= v
	}
}

func blockMix(b, y []byte, r int) {
	var x [64]byte

	blockCopy(x[:], b[(2*r-1)*64:], 64)

	for i := 0; i < 2*r*64; i += 64 {
		blockXOR(x[:], b[i:], 64)
		salsa.Core208(&x, &x)
		blockCopy(y[i:], x[:], 64)
	}

	for i := 0; i < r; i++ {
		blockCopy(b[i*64:], y[i*2*64:], 64)
	}

	for i := 0; i < r; i++ {
		blockCopy(b[(i+r)*64:], y[(i*2+1)*64:], 64)
	}
}

func integer(b []byte, r int) uint64 {
	return binary.LittleEndian.Uint64(b[(2*r-1)*64:])
}

func smix(b []byte, r, N int, v, xy []byte) {
	x := xy
	y := xy[128*r:]

	blockCopy(x, b, 128*r)

	for i := 0; i < N; i++ {
		blockCopy(v[i*128*r:], x, 128*r)
		blockMix(x, y, r)
	}

	for i := 0; i < N; i++ {
		j := int(integer(x, r) & uint64(N-1))
		blockXOR(x, v[j*128*r:], 128*r)
		blockMix(x, y, r)
	}

	blockCopy(b, x, 128*r)
}

// Key derives a key from the password, salt, and cost parameters, returning
// a byte slice of length keyLen that can be used as cryptographic key.
// 
// N is a CPU/memory cost parameter, which must be a power of two greater than 1.
// r and p must satisfy r * p < 2³⁰. If the parameters do not satisfy the
// limits, the function returns a nil byte slice and an error.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//      dk := scrypt.Key([]byte("some password"), salt, 16384, 8, 1, 32)
//
// The recommended parameters for interactive logins as of 2009 are N=16384,
// r=8, p=1. They should be increased as memory latency and CPU parallelism
// increases. Remember to get a good random salt.
func Key(password, salt []byte, N, r, p, keyLen int) ([]byte, error) {
	if N <= 1 || N&(N-1) != 0 {
		return nil, errors.New("scrypt: N must be > 1 and a power of 2")
	}
	if uint64(r)*uint64(p) >= 1<<30 || r > maxInt/128/p || r > maxInt/256 || N > maxInt/128/r {
		return nil, errors.New("scrypt: parameters are too large")
	}

	xy := make([]byte, 256*r)
	v := make([]byte, 128*r*N)
	b := pbkdf2.Key(password, salt, 1, p*128*r, sha256.New)

	for i := 0; i < p; i++ {
		smix(b[i*128*r:], r, N, v, xy)
	}

	return pbkdf2.Key(password, b, 1, keyLen, sha256.New), nil
}
