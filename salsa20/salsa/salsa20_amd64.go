// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!purego,gc

package salsa

//go:noescape

// salsa20nXORKeyStream is implemented in salsa20_amd64.s.
func salsa20nXORKeyStream(out, in *byte, n uint64, nonce, key *byte, rounds uint64)

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out must overlap entirely or not at all. Counter
// contains the raw salsa20 counter bytes (both nonce and block counter).
func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	if len(in) == 0 {
		return
	}
	_ = out[len(in)-1] // fail if the length of out is shorter than in
	salsa20nXORKeyStream(&out[0], &in[0], uint64(len(in)), &counter[0], &key[0], uint64(20))
}

func XORKeyStreamWithRounds(out, in []byte, counter *[16]byte, key *[32]byte, rounds uint64) {
	if len(in) == 0 {
		return
	}
	_ = out[len(in)-1] // fail if the length of out is shorter than in
	salsa20nXORKeyStream(&out[0], &in[0], uint64(len(in)), &counter[0], &key[0], rounds)
}
