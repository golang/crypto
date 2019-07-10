// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package chacha20 implements the ChaCha20 encryption algorithm
// as specified in RFC 8439.
package chacha20

import (
	"crypto/cipher"
	"encoding/binary"
	"math/bits"

	"golang.org/x/crypto/internal/subtle"
)

// Cipher is a stateful instance of ChaCha20 using a particular key
// and nonce. A *Cipher implements the cipher.Stream interface.
type Cipher struct {
	// The ChaCha20 state is 16 words: 4 constant, 8 of key, 1 of counter
	// (incremented after each block), and 3 of nonce.
	key     [8]uint32
	counter uint32
	nonce   [3]uint32

	// The last len bytes of buf are leftover key stream bytes from the previous
	// XORKeyStream invocation. The size of buf depends on how many blocks are
	// computed at a time.
	buf [bufSize]byte
	len int
}

var _ cipher.Stream = (*Cipher)(nil)

// New creates a new ChaCha20 stream cipher with the given key and nonce.
// The initial counter value is set to 0.
func New(key [8]uint32, nonce [3]uint32) *Cipher {
	return &Cipher{key: key, nonce: nonce}
}

// The constant first 4 words of the ChaCha20 state.
const (
	j0 uint32 = 0x61707865 // expa
	j1 uint32 = 0x3320646e // nd 3
	j2 uint32 = 0x79622d32 // 2-by
	j3 uint32 = 0x6b206574 // te k
)

const blockSize = 64

// quarterRound is the core of ChaCha20. It shuffles the bits of 4 state words.
// It's executed 4 times for each of the 20 ChaCha20 rounds, operating on all 16
// words each round, in columnar or diagonal groups of 4 at a time.
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream. Dst and src must overlap entirely or not at all.
//
// If len(dst) < len(src), XORKeyStream will panic. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
//
// Multiple calls to XORKeyStream behave as if the concatenation of
// the src buffers was passed in a single run. That is, Cipher
// maintains state and does not reset at each XORKeyStream call.
func (s *Cipher) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("chacha20: output smaller than input")
	}
	dst = dst[:len(src)]
	if subtle.InexactOverlap(dst, src) {
		panic("chacha20: invalid buffer overlap")
	}

	// First, drain any remaining key stream from a previous XORKeyStream.
	if s.len != 0 {
		keyStream := s.buf[bufSize-s.len:]
		if len(src) < len(keyStream) {
			keyStream = keyStream[:len(src)]
		}
		_ = src[len(keyStream)-1] // bounds check elimination hint
		for i, b := range keyStream {
			dst[i] = src[i] ^ b
		}
		s.len -= len(keyStream)
		src = src[len(keyStream):]
		dst = dst[len(keyStream):]
	}

	const blocksPerBuf = bufSize / blockSize
	numBufs := (uint64(len(src)) + bufSize - 1) / bufSize
	if uint64(s.counter)+numBufs*blocksPerBuf >= 1<<32 {
		panic("chacha20: counter overflow")
	}

	// xorKeyStreamBlocks implementations expect input lengths that are a
	// multiple of bufSize. Platform-specific ones process multiple blocks at a
	// time, so have bufSizes that are a multiple of blockSize.

	rem := len(src) % bufSize
	full := len(src) - rem

	if full > 0 {
		s.xorKeyStreamBlocks(dst[:full], src[:full])
	}

	// If we have a partial (multi-)block, pad it for xorKeyStreamBlocks, and
	// keep the leftover keystream for the next XORKeyStream invocation.
	if rem > 0 {
		s.buf = [bufSize]byte{}
		copy(s.buf[:], src[full:])
		s.xorKeyStreamBlocks(s.buf[:], s.buf[:])
		s.len = bufSize - copy(dst[full:], s.buf[:])
	}
}

func (s *Cipher) xorKeyStreamBlocksGeneric(dst, src []byte) {
	if len(dst) != len(src) || len(dst)%blockSize != 0 {
		panic("chacha20: internal error: wrong dst and/or src length")
	}

	// To generate each block of key stream, the initial cipher state
	// (represented below) is passed through 20 rounds of shuffling,
	// alternatively applying quarterRounds by columns (like 1, 5, 9, 13)
	// or by diagonals (like 1, 6, 11, 12).
	//
	//      0:cccccccc   1:cccccccc   2:cccccccc   3:cccccccc
	//      4:kkkkkkkk   5:kkkkkkkk   6:kkkkkkkk   7:kkkkkkkk
	//      8:kkkkkkkk   9:kkkkkkkk  10:kkkkkkkk  11:kkkkkkkk
	//     12:bbbbbbbb  13:nnnnnnnn  14:nnnnnnnn  15:nnnnnnnn
	//
	//            c=constant k=key b=blockcount n=nonce
	var (
		c0, c1, c2, c3   = j0, j1, j2, j3
		c4, c5, c6, c7   = s.key[0], s.key[1], s.key[2], s.key[3]
		c8, c9, c10, c11 = s.key[4], s.key[5], s.key[6], s.key[7]
		_, c13, c14, c15 = s.counter, s.nonce[0], s.nonce[1], s.nonce[2]
	)

	// Three quarters of the first round don't depend on the counter, so we can
	// calculate them here, and reuse them for multiple blocks in the loop.
	// TODO(filippo): experiment with reusing across XORKeyStream calls.
	s1, s5, s9, s13 := quarterRound(c1, c5, c9, c13)
	s2, s6, s10, s14 := quarterRound(c2, c6, c10, c14)
	s3, s7, s11, s15 := quarterRound(c3, c7, c11, c15)

	for i := 0; i < len(src); i += blockSize {
		// The remainder of the first column round.
		s0, s4, s8, s12 := quarterRound(c0, c4, c8, s.counter)

		// The second diagonal round.
		x0, x5, x10, x15 := quarterRound(s0, s5, s10, s15)
		x1, x6, x11, x12 := quarterRound(s1, s6, s11, s12)
		x2, x7, x8, x13 := quarterRound(s2, s7, s8, s13)
		x3, x4, x9, x14 := quarterRound(s3, s4, s9, s14)

		// The remaining 18 rounds.
		for i := 0; i < 9; i++ {
			// Column round.
			x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarterRound(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarterRound(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarterRound(x3, x7, x11, x15)

			// Diagonal round.
			x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarterRound(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarterRound(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarterRound(x3, x4, x9, x14)
		}

		// Finally, add back the initial state to generate the key stream.
		x0 += c0
		x1 += c1
		x2 += c2
		x3 += c3
		x4 += c4
		x5 += c5
		x6 += c6
		x7 += c7
		x8 += c8
		x9 += c9
		x10 += c10
		x11 += c11
		x12 += s.counter
		x13 += c13
		x14 += c14
		x15 += c15

		s.counter += 1
		if s.counter == 0 {
			panic("chacha20: internal error: counter overflow")
		}

		in, out := src[i:], dst[i:]
		in, out = in[:blockSize], out[:blockSize] // bounds check elimination hint

		// XOR the key stream with the source and write out the result.
		xor(out[0:], in[0:], x0)
		xor(out[4:], in[4:], x1)
		xor(out[8:], in[8:], x2)
		xor(out[12:], in[12:], x3)
		xor(out[16:], in[16:], x4)
		xor(out[20:], in[20:], x5)
		xor(out[24:], in[24:], x6)
		xor(out[28:], in[28:], x7)
		xor(out[32:], in[32:], x8)
		xor(out[36:], in[36:], x9)
		xor(out[40:], in[40:], x10)
		xor(out[44:], in[44:], x11)
		xor(out[48:], in[48:], x12)
		xor(out[52:], in[52:], x13)
		xor(out[56:], in[56:], x14)
		xor(out[60:], in[60:], x15)
	}
}

// Advance discards bytes in the key stream until the next 64 byte block
// boundary is reached. If the key stream is already at a block boundary no
// bytes will be discarded.
func (s *Cipher) Advance() {
	s.len -= s.len % blockSize
}

// XORKeyStream crypts bytes from in to out using the given key and counters.
// In and out must overlap entirely or not at all. Counter contains the raw
// ChaCha20 counter bytes (i.e. block counter followed by nonce).
func XORKeyStream(out, in []byte, counter *[16]byte, key *[32]byte) {
	s := Cipher{
		key: [8]uint32{
			binary.LittleEndian.Uint32(key[0:4]),
			binary.LittleEndian.Uint32(key[4:8]),
			binary.LittleEndian.Uint32(key[8:12]),
			binary.LittleEndian.Uint32(key[12:16]),
			binary.LittleEndian.Uint32(key[16:20]),
			binary.LittleEndian.Uint32(key[20:24]),
			binary.LittleEndian.Uint32(key[24:28]),
			binary.LittleEndian.Uint32(key[28:32]),
		},
		nonce: [3]uint32{
			binary.LittleEndian.Uint32(counter[4:8]),
			binary.LittleEndian.Uint32(counter[8:12]),
			binary.LittleEndian.Uint32(counter[12:16]),
		},
		counter: binary.LittleEndian.Uint32(counter[0:4]),
	}
	s.XORKeyStream(out, in)
}

// HChaCha20 uses the ChaCha20 core to generate a derived key from a key and a
// nonce. It should only be used as part of the XChaCha20 construction.
func HChaCha20(key *[8]uint32, nonce *[4]uint32) [8]uint32 {
	x0, x1, x2, x3 := j0, j1, j2, j3
	x4, x5, x6, x7 := key[0], key[1], key[2], key[3]
	x8, x9, x10, x11 := key[4], key[5], key[6], key[7]
	x12, x13, x14, x15 := nonce[0], nonce[1], nonce[2], nonce[3]

	for i := 0; i < 10; i++ {
		// Diagonal round.
		x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
		x1, x5, x9, x13 = quarterRound(x1, x5, x9, x13)
		x2, x6, x10, x14 = quarterRound(x2, x6, x10, x14)
		x3, x7, x11, x15 = quarterRound(x3, x7, x11, x15)

		// Column round.
		x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
		x1, x6, x11, x12 = quarterRound(x1, x6, x11, x12)
		x2, x7, x8, x13 = quarterRound(x2, x7, x8, x13)
		x3, x4, x9, x14 = quarterRound(x3, x4, x9, x14)
	}

	var out [8]uint32
	out[0], out[1], out[2], out[3] = x0, x1, x2, x3
	out[4], out[5], out[6], out[7] = x12, x13, x14, x15
	return out
}
