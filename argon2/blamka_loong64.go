// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build loong64 && gc && !purego

package argon2

import "golang.org/x/sys/cpu"

//go:noescape
func mixBlocks1VX(out, in1, in2 *block)

//go:noescape
func mixBlocks2VX(out, in1, in2, t *block)

//go:noescape
func xorBlocksVX(out, in1, in2, t *block)

//go:noescape
func blamkaVX(b *block)

func processBlockVX(out, in1, in2 *block, xor bool) {
	var t block
	mixBlocks1VX(&t, in1, in2)
	if cpu.Loong64.HasLSX {
		blamkaVX(&t)
	} else {
		for i := 0; i < blockLength; i += 16 {
			blamkaGeneric(
				&t[i+0], &t[i+1], &t[i+2], &t[i+3],
				&t[i+4], &t[i+5], &t[i+6], &t[i+7],
				&t[i+8], &t[i+9], &t[i+10], &t[i+11],
				&t[i+12], &t[i+13], &t[i+14], &t[i+15],
			)
		}
		for i := 0; i < blockLength/8; i += 2 {
			blamkaGeneric(
				&t[i], &t[i+1], &t[16+i], &t[16+i+1],
				&t[32+i], &t[32+i+1], &t[48+i], &t[48+i+1],
				&t[64+i], &t[64+i+1], &t[80+i], &t[80+i+1],
				&t[96+i], &t[96+i+1], &t[112+i], &t[112+i+1],
			)
		}
	}
	if xor {
		xorBlocksVX(out, in1, in2, &t)
	} else {
		mixBlocks2VX(out, in1, in2, &t)
	}
}

func processBlock(out, in1, in2 *block) {
	processBlockVX(out, in1, in2, false)
}

func processBlockXOR(out, in1, in2 *block) {
	processBlockVX(out, in1, in2, true)
}
