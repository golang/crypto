// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build loong64 && gc && !purego

#include "textflag.h"

#define BLAMKA_ROUND \
	VMULWEVVWU	V0, V2, V8; \
	VADDV		V2, V0, V0; \
	VADDV		V0, V8, V0; \
	VADDV		V0, V8, V0; \
	VXORV		V6, V0, V6; \
	VROTRV		$32, V6, V6; \
	VMULWEVVWU	V4, V6, V8; \
	VADDV		V4, V6, V4; \
	VADDV		V4, V8, V4; \
	VADDV		V4, V8, V4; \
	VXORV		V2, V4, V2; \
	VROTRV		$24, V2, V2; \
	VMULWEVVWU	V0, V2, V8; \
	VADDV		V0, V2, V0; \
	VADDV		V0, V8, V0; \
	VADDV		V0, V8, V0; \
	VXORV		V6, V0, V6; \
	VROTRV		$16, V6, V6; \
	VMULWEVVWU	V4, V6, V8; \
	VADDV		V4, V6, V4; \
	VADDV		V4, V8, V4; \
	VADDV		V4, V8, V4; \
	VXORV		V2, V4, V2; \
	VROTRV		$63, V2, V2; \
;\
	VMULWEVVWU	V1, V3, V8; \
	VADDV		V1, V3, V1; \
	VADDV		V1, V8, V1; \
	VADDV		V1, V8, V1; \
	VXORV		V7, V1, V7; \
	VROTRV		$32, V7, V7; \
	VMULWEVVWU	V5, V7, V8; \
	VADDV		V5, V7, V5; \
	VADDV		V5, V8, V5; \
	VADDV		V5, V8, V5; \
	VXORV		V3, V5, V3; \
	VROTRV		$24, V3, V3; \
	VMULWEVVWU	V1, V3, V8; \
	VADDV		V1, V3, V1; \
	VADDV		V1, V8, V1; \
	VADDV		V1, V8, V1; \
	VXORV		V7, V1, V7; \
	VROTRV		$16, V7, V7; \
	VMULWEVVWU	V5, V7, V8; \
	VADDV		V5, V7, V5; \
	VADDV		V5, V8, V5; \
	VADDV		V5, V8, V5; \
	VXORV		V3, V5, V3; \
	VROTRV		$63, V3, V3; \
;\
	VXORV		V0, V0, V8; \	// V8 = 0
	VADDV		V2, V8, V9; \	// V9 = V2
	VADDV		V5, V8, V10; \	// V10 = V5
	VADDV		V6, V8, V11; \	// V11 = V6
	VADDV		V4, V8, V5; \	// V5 = V4
	VADDV		V10, V8, V4; \	// V4 = V5
	VSHUF4IV	$9, V3, V2; \
	VSHUF4IV	$9, V9, V3; \
	VSHUF4IV	$3, V7, V6; \
	VSHUF4IV	$3, V11, V7; \
;\
	VMULWEVVWU	V0, V2, V9; \
	VADDV		V0, V2, V0; \
	VADDV		V0, V9, V0; \
	VADDV		V0, V9, V0; \
	VXORV		V6, V0, V6; \
	VROTRV		$32, V6, V6; \
	VMULWEVVWU	V4, V6, V9; \
	VADDV		V4, V6, V4; \
	VADDV		V4, V9, V4; \
	VADDV		V4, V9, V4; \
	VXORV		V2, V4, V2; \
	VROTRV		$24, V2, V2; \
	VMULWEVVWU	V0, V2, V9; \
	VADDV		V0, V2, V0; \
	VADDV		V0, V9, V0; \
	VADDV		V0, V9, V0; \
	VXORV		V6, V0, V6; \
	VROTRV		$16, V6, V6; \
	VMULWEVVWU	V4, V6, V9; \
	VADDV		V4, V6, V4; \
	VADDV		V4, V9, V4; \
	VADDV		V4, V9, V4; \
	VXORV		V2, V4, V2; \
	VROTRV		$63, V2, V2; \
;\
	VMULWEVVWU	V1, V3, V9; \
	VADDV		V1, V3, V1; \
	VADDV		V1, V9, V1; \
	VADDV		V1, V9, V1; \
	VXORV		V7, V1, V7; \
	VROTRV		$32, V7, V7; \
	VMULWEVVWU	V5, V7, V9; \
	VADDV		V5, V7, V5; \
	VADDV		V5, V9, V5; \
	VADDV		V5, V9, V5; \
	VXORV		V3, V5, V3; \
	VROTRV		$24, V3, V3; \
	VMULWEVVWU	V1, V3, V9; \
	VADDV		V1, V3, V1; \
	VADDV		V1, V9, V1; \
	VADDV		V1, V9, V1; \
	VXORV		V7, V1, V7; \
	VROTRV		$16, V7, V7; \
	VMULWEVVWU	V5, V7, V9; \
	VADDV		V5, V7, V5; \
	VADDV		V5, V9, V5; \
	VADDV		V5, V9, V5; \
	VXORV		V3, V5, V3; \
	VROTRV		$63, V3, V3; \
;\
	VADDV		V2, V8, V9; \	// V9 = V2
	VADDV		V5, V8, V10; \	// V10 = V5
	VADDV		V6, V8, V11; \	// V11 = V6
	VADDV		V4, V8, V5; \	// V5 = V4
	VADDV		V10, V8, V4; \	// V4 = V5
	VSHUF4IV	$3, V3, V2; \
	VSHUF4IV	$3, V9, V3; \
	VSHUF4IV	$9, V7, V6; \
	VSHUF4IV	$9, V11, V7; \

#define BLAMKA_ROUND1(index) \
	VMOVQ	(index+0)(R4), V0; \
	VMOVQ	(index+16)(R4), V1; \
	VMOVQ	(index+32)(R4), V2; \
	VMOVQ	(index+48)(R4), V3; \
	VMOVQ	(index+64)(R4), V4; \
	VMOVQ	(index+80)(R4), V5; \
	VMOVQ	(index+96)(R4), V6; \
	VMOVQ	(index+112)(R4), V7; \
	BLAMKA_ROUND; \
	VMOVQ	V0, (index+0)(R4); \
	VMOVQ	V1, (index+16)(R4); \
	VMOVQ	V2, (index+32)(R4); \
	VMOVQ	V3, (index+48)(R4); \
	VMOVQ	V4, (index+64)(R4); \
	VMOVQ	V5, (index+80)(R4); \
	VMOVQ	V6, (index+96)(R4); \
	VMOVQ	V7, (index+112)(R4); \

#define BLAMKA_ROUND2(index) \
	VMOVQ	(index+0)(R4), V0; \
	VMOVQ	(index+128)(R4), V1; \
	VMOVQ	(index+256)(R4), V2; \
	VMOVQ	(index+384)(R4), V3; \
	VMOVQ	(index+512)(R4), V4; \
	VMOVQ	(index+640)(R4), V5; \
	VMOVQ	(index+768)(R4), V6; \
	VMOVQ	(index+896)(R4), V7; \
	BLAMKA_ROUND; \
	VMOVQ	V0, (index+0)(R4); \
	VMOVQ	V1, (index+128)(R4); \
	VMOVQ	V2, (index+256)(R4); \
	VMOVQ	V3, (index+384)(R4); \
	VMOVQ	V4, (index+512)(R4); \
	VMOVQ	V5, (index+640)(R4); \
	VMOVQ	V6, (index+768)(R4); \
	VMOVQ	V7, (index+896)(R4); \

// func blamkaVX(b *block)
TEXT ·blamkaVX(SB), NOSPLIT, $0-8
	MOVV	b+0(FP), R4

	BLAMKA_ROUND1(0)
	BLAMKA_ROUND1(128)
	BLAMKA_ROUND1(256)
	BLAMKA_ROUND1(384)
	BLAMKA_ROUND1(512)
	BLAMKA_ROUND1(640)
	BLAMKA_ROUND1(768)
	BLAMKA_ROUND1(896)

	BLAMKA_ROUND2(0)
	BLAMKA_ROUND2(16)
	BLAMKA_ROUND2(32)
	BLAMKA_ROUND2(48)
	BLAMKA_ROUND2(64)
	BLAMKA_ROUND2(80)
	BLAMKA_ROUND2(96)
	BLAMKA_ROUND2(112)

	RET

// func mixBlocks1VX(t *block, in1 *block, in2 *block)
TEXT ·mixBlocks1VX(SB), NOSPLIT, $0-24
	MOVV	t+0(FP), R4
	MOVV	in1+8(FP), R5
	MOVV	in2+16(FP), R6
	MOVV	$128, R8

loop:
	VMOVQ	(R5), V0
	VMOVQ	(R6), V1
	VXORV	V0, V1, V2
	VMOVQ	V2, (R4)
	ADDV	$16, R5
	ADDV	$16, R6
	ADDV	$16, R4
	SUBV	$2, R8
	BLT	R0, R8, loop
	RET

// func mixBlocks2VX(out *block, in1 *block, in2 *block, t *block)
TEXT ·mixBlocks2VX(SB), NOSPLIT, $0-32
	MOVV	out+0(FP), R4
	MOVV	in1+8(FP), R5
	MOVV	in2+16(FP), R6
	MOVV	t+24(FP), R7
	MOVV	$128, R8

loop:
	VMOVQ	(R5), V0
	VMOVQ	(R6), V1
	VMOVQ	(R7), V2
	VXORV	V0, V1, V3
	VXORV	V3, V2, V4
	VMOVQ	V4, (R4)
	ADDV	$16, R5
	ADDV	$16, R6
	ADDV	$16, R7
	ADDV	$16, R4
	SUBV	$2, R8
	BLT	R0, R8, loop
	RET

// func xorBlocksVX(out *block, in1 *block, in2 *block, t *block)
TEXT ·xorBlocksVX(SB), NOSPLIT, $0-32
	MOVV	out+0(FP), R4
	MOVV	in1+8(FP), R5
	MOVV	in2+16(FP), R6
	MOVV	t+24(FP), R7
	MOVV	$128, R8

loop:
	VMOVQ	(R5), V0
	VMOVQ	(R6), V1
	VMOVQ	(R7), V2
	VMOVQ	(R4), V3
	VXORV	V0, V1, V4
	VXORV	V4, V2, V5
	VXORV	V5, V3, V6
	VMOVQ	V6, (R4)
	ADDV	$16, R5
	ADDV	$16, R6
	ADDV	$16, R7
	ADDV	$16, R4
	SUBV	$2, R8
	BLT	R0, R8, loop
	RET
