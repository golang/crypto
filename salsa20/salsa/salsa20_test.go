// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build (amd64 || loong64) && !purego && gc

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

// TestUnalignedLengths verifies that input lengths that are not multiples of
// the 256-byte main loop produce the same keystream as the generic
// implementation. This is a regression test for the LoongArch LSX keystream
// reuse bug (golang/go#81939), where the <256-byte tail reused the keystream
// vectors of the previous 256-byte iteration instead of generating fresh
// blocks.
func TestUnalignedLengths(t *testing.T) {
	key := &[32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5,
		6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}
	counter := &[16]byte{0, 1, 2, 3, 4, 5, 6, 7}

	// Sweep every length up to 2*256+64 so that every tail branch
	// (128/64/32/16/8/4/2/1) is exercised both with and without a
	// preceding full 256-byte iteration. Include the reported
	// reproducer length 257 and boundary cases explicitly.
	sizes := []int{0, 1, 255, 256, 257, 384, 511, 512, 513, 767, 768, 769}
	for n := 1; n <= 2*256+64; n++ {
		sizes = append(sizes, n)
	}

	for _, n := range sizes {
		in := make([]byte, n)
		for i := range in {
			in[i] = byte(i)
		}
		out := make([]byte, n)
		outGeneric := make([]byte, n)
		XORKeyStream(out, in, counter, key)
		genericXORKeyStream(outGeneric, in, counter, key)
		if !bytes.Equal(out, outGeneric) {
			t.Errorf("n=%d: assembly and go implementations disagree", n)
		}
	}
}
