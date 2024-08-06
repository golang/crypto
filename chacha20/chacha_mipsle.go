// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build gc && !purego

package chacha20

const bufSize = blockSize

//go:noescape
func xorKeyStream(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter *uint32)

func (s *Cipher) xorKeyStreamBlocks(dst, src []byte) {
	xorKeyStream(dst, src, &s.key, &s.nonce, &s.counter)
}
