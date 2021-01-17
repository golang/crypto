// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build amd64,!purego,gc

package salsa

import (
	"bytes"
	"testing"
)

func TestCounterOverflow(t *testing.T) {
	in := make([]byte, 4096)
	key := &[32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
		6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}
	for n, counter := range []*[16]byte{
		&[16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0, 0, 0, 0},             // zero counter
		&[16]byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, // counter about to overflow 32 bits
		&[16]byte{0, 1, 2, 3, 4, 5, 6, 7, 1, 2, 3, 4, 0xff, 0xff, 0xff, 0xff}, // counter above 32 bits
	} {
		out := make([]byte, 4096)
		XORKeyStream(out, in, counter, key)
		outGeneric := make([]byte, 4096)
		genericXORKeyStream(outGeneric, in, counter, key)
		if !bytes.Equal(out, outGeneric) {
			t.Errorf("%d: assembly and go implementations disagree", n)
		}
	}
}

func benchmarkSalsa20amd(i int, b *testing.B) {
	in512 := make([]byte, 512)
	counter := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}
	out_XOR := make([]byte, 512)
	for n := 0; n < b.N; n++ {
		salsa20nXORKeyStream(&out_XOR[0], &in512[0], uint64(len(in512)), &counter[0], &key32[0], uint64(i))
	}
}
func BenchmarkSalsa20_04_amd64(b *testing.B) { benchmarkSalsa20amd(4, b) }
func BenchmarkSalsa20_08_amd64(b *testing.B) { benchmarkSalsa20amd(8, b) }
func BenchmarkSalsa20_12_amd64(b *testing.B) { benchmarkSalsa20amd(12, b) }
func BenchmarkSalsa20_16_amd64(b *testing.B) { benchmarkSalsa20amd(16, b) }
func BenchmarkSalsa20_20_amd64(b *testing.B) { benchmarkSalsa20amd(20, b) }
func BenchmarkSalsa20_24_amd64(b *testing.B) { benchmarkSalsa20amd(24, b) }

// TestXORKeyStream applies the Salsa20 XOR Key Stream function to input in, key,
// and 16-byte constant c, and tests the result to verify 20/12/8 are functioning properly.
func TestXORKeyStream_amd(t *testing.T) {
	in512 := make([]byte, 512)

	counter := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5}

	// The default calls used externally:
	// XORKeyStream uses the default 20 rounds
	out_XOR := make([]byte, 512)
	XORKeyStream(out_XOR, in512, &counter, &key32)
	if !testEq(out_XOR, out512_test20) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test20, out_XOR)
	}

	// XORKeyStreamWithRounds specifying 20 rounds
	out_XOR = make([]byte, 512)
	XORKeyStreamWithRounds(out_XOR, in512, &counter, &key32, 20)
	if !testEq(out_XOR, out512_test20) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test20, out_XOR)
	}

	// XORKeyStreamWithRounds specifying 12 rounds
	out_XOR = make([]byte, 512)
	XORKeyStreamWithRounds(out_XOR, in512, &counter, &key32, 12)
	if !testEq(out_XOR, out512_test12) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test12, out_XOR)
	}

	// XORKeyStreamWithRounds specifying 8 rounds
	out_XOR = make([]byte, 512)
	XORKeyStreamWithRounds(out_XOR, in512, &counter, &key32, 8)
	if !testEq(out_XOR, out512_test8) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test8, out_XOR)
	}

	// noasm genericXORKeyStream(out, in, counter, key) using default 20 rounds
	out_XOR = make([]byte, 512)
	genericXORKeyStream(out_XOR, in512, &counter, &key32)
	if !testEq(out_XOR, out512_test20) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test20, out_XOR)
	}

	// noasm genericXORKeyStream(out, in, counter, key, rounds) with 20 rounds
	out_XOR = make([]byte, 512)
	generic20nXORKeyStream(out_XOR, in512, &counter, &key32, 20)
	if !testEq(out_XOR, out512_test20) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test20, out_XOR)
	}

	// asm salsa20nXORKeyStream(out, in *byte, n uint64, nonce, key *byte, rounds uint64) with 20 rounds
	out_XOR = make([]byte, 512)
	salsa20nXORKeyStream(&out_XOR[0], &in512[0], uint64(len(in512)), &counter[0], &key32[0], uint64(20))
	if !testEq(out_XOR, out512_test20) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test20, out_XOR)
	}

	// noasm genericXORKeyStream(out, in, counter, key, rounds) with 12 rounds
	out_XOR = make([]byte, 512)
	generic20nXORKeyStream(out_XOR, in512, &counter, &key32, 12)
	if !testEq(out_XOR, out512_test12) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test12, out_XOR)
	}

	// asm salsa20nXORKeyStream(out, in *byte, n uint64, nonce, key *byte, rounds uint64) with 12 rounds
	out_XOR = make([]byte, 512)
	salsa20nXORKeyStream(&out_XOR[0], &in512[0], uint64(len(in512)), &counter[0], &key32[0], uint64(12))
	if !testEq(out_XOR, out512_test12) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test12, out_XOR)
	}

	// noasm genericXORKeyStream(out, in, counter, key, rounds) with 8 rounds
	out_XOR = make([]byte, 512)
	generic20nXORKeyStream(out_XOR, in512, &counter, &key32, 8)
	if !testEq(out_XOR, out512_test8) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test8, out_XOR)
	}

	// asm salsa20nXORKeyStream(out, in *byte, n uint64, nonce, key *byte, rounds uint64) with 8 rounds
	out_XOR = make([]byte, 512)
	salsa20nXORKeyStream(&out_XOR[0], &in512[0], uint64(len(in512)), &counter[0], &key32[0], uint64(8))
	if !testEq(out_XOR, out512_test8) {
		t.Errorf("\nexpected: % 02x,\n     got: % 02x", out512_test8, out_XOR)
	}
}
