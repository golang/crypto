// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Ported from https://github.com/torvalds/linux/blob/1b294a1f35616977caddaddf3e9d28e576a1adbc/arch/mips/crypto/chacha-core.S
// which is licensed under:
// # ====================================================================
// # SPDX-License-Identifier: GPL-2.0 OR MIT
// #
// # Copyright (C) 2016-2018 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
// # Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
// # ====================================================================

//go:build gc && !purego

#include "textflag.h"

#define X0	R1
#define X1	R2
#define X2	R3
#define X3	R4
#define X4	R5
#define X5	R6
#define X6	R7
#define X7	R8
#define X8	R9
#define X9	R10
#define X10	R11
#define X11	R12
#define X12	R13
#define X13	R14
#define X14	R15
#define X15	R16

#define DST 		R17
#define SRC 		R18
#define SRC_LEN 	R19
#define KEY			R20
#define NONCE 		R21
#define CTR			R22

#define LOOP_I		R24
#define TMP			R25

#ifdef GOMIPS_r2
#define hasROTR
#endif
#ifdef GOMIPS_r5
#define hasROTR
#endif

#ifdef hasROTR
#define ROTL(S, R) 			\
	ROTR	$(32-S), R
#else
#define ROTL(S, R) 			\
	SLL		$(S), R, TMP	\
	SRL		$(32-S), R 		\
	OR 		TMP, R
#endif

#define AXR(A, B, C, D,  K, L, M, N,  V, W, Y, Z,  S) \
	ADDU	K, A 	\
	ADDU	L, B 	\
	ADDU	M, C 	\
	ADDU	N, D 	\
	XOR		A, V 	\
	XOR		B, W 	\
	XOR		C, Y 	\
	XOR		D, Z 	\
	ROTL	(S, V) 	\
	ROTL	(S, W) 	\
	ROTL	(S, Y) 	\
	ROTL	(S, Z)

#define FOR_STATE(OP, OP_MEM) \
	OP (    $0x61707865,	X0 ) 	\ // expa
	OP (    $0x3320646e,	X1 ) 	\ // nd 3
	OP (    $0x79622d32, 	X2 ) 	\ // 2-by
	OP (	$0x6b206574,	X3 ) 	\ // te k
	OP_MEM (	0(KEY), 	X4 ) 	\
	OP_MEM (    4(KEY), 	X5 ) 	\
	OP_MEM (    8(KEY), 	X6 ) 	\
	OP_MEM (    12(KEY), 	X7 ) 	\
	OP_MEM (    16(KEY), 	X8 ) 	\
	OP_MEM (    20(KEY), 	X9 ) 	\
	OP_MEM (    24(KEY),	X10 ) 	\
	OP_MEM (    28(KEY),	X11 ) 	\
	OP (    	CTR,		X12 ) 	\
	OP_MEM (    0(NONCE),	X13 ) 	\
	OP_MEM (    4(NONCE),	X14 ) 	\
	OP_MEM (    8(NONCE),	X15 )

#define movw(x, y) \
	MOVW x, y

#define ADD(V, REG)  \
	ADDU	V, REG

#define ADD_MEM(ADDR, REG)  \
	MOVW    ADDR, TMP 		\
	ADDU	TMP, REG

// XOR_STREAM_WORD works with unaligned memory, this is quite important since the strams might not be aligned.
// Especially during the use in TLS the memory is often unaligned.
#define XOR_STREAM_WORD( OFF, REG) 	\
	MOVWL	(4*OFF + 3)(SRC), TMP 	\
	MOVWR	(4*OFF)(SRC), TMP 		\
	XOR		REG, TMP				\ 
	MOVWL	TMP, (4*OFF + 3)(DST) 	\
	MOVWR	TMP, (4*OFF)(DST)

// func xorKeyStream(dst, src []byte, key *[8]uint32, nonce *[3]uint32, counter *uint32)
TEXT ·xorKeyStream(SB), NOSPLIT|NOFRAME, $0
	MOVW	dst+0(FP), 		DST
	MOVW	src+12(FP), 	SRC
	MOVW	src_len+16(FP), SRC_LEN
	MOVW	key+24(FP),		KEY
	MOVW	nonce+28(FP),	NONCE
	MOVW	counter+32(FP), CTR

	// load counter
	MOVW	(CTR), CTR

chacha:

	// load initial State into X*
	FOR_STATE ( movw, movw )

	// set number of rounds
	MOVW	$20, LOOP_I

loop:
	AXR( X0,X1,X2,X3,		X4,X5,X6,X7,		X12,X13,X14,X15,	16)
	AXR( X8,X9,X10,X11,		X12,X13,X14,X15,	X4,X5,X6,X7,		12)
	AXR( X0,X1,X2,X3,		X4,X5,X6,X7,		X12,X13,X14,X15,	8)
	AXR( X8,X9,X10,X11,		X12,X13,X14,X15,	X4,X5,X6,X7,  		7)
	AXR( X0,X1,X2,X3,		X5,X6,X7,X4,		X15,X12,X13,X14,	16)
	AXR( X10,X11,X8,X9,		X15,X12,X13,X14,	X5,X6,X7,X4, 		12)
	AXR( X0,X1,X2,X3,		X5,X6,X7,X4,		X15,X12,X13,X14,	8)
	AXR( X10,X11,X8,X9,		X15,X12,X13,X14,	X5,X6,X7,X4,  		7)

	ADDU	$-2, LOOP_I
	BNE     LOOP_I, loop

	// add back the initial state to generate the key stream
	FOR_STATE ( ADD, ADD_MEM )

	// xor the key stream with the source and write out the result
	XOR_STREAM_WORD (0, X0)
	XOR_STREAM_WORD (1, X1)
	XOR_STREAM_WORD (2, X2)
	XOR_STREAM_WORD (3, X3)
	XOR_STREAM_WORD (4, X4)
	XOR_STREAM_WORD (5, X5)
	XOR_STREAM_WORD (6, X6)
	XOR_STREAM_WORD (7, X7)
	XOR_STREAM_WORD (8, X8)
	XOR_STREAM_WORD (9, X9)
	XOR_STREAM_WORD (10, X10)
	XOR_STREAM_WORD (11, X11)
	XOR_STREAM_WORD (12, X12)
	XOR_STREAM_WORD (13, X13)
	XOR_STREAM_WORD (14, X14)
	XOR_STREAM_WORD (15, X15)

	// decrement length
	ADDU	$-64, SRC_LEN, SRC_LEN

	// increment pointers
	MOVW 	$64(DST), DST
	MOVW	$64(SRC), SRC

	// increment counter
	ADDU	$1, CTR

	// loop if there's still data
	BNE     SRC_LEN, chacha

	// store Counter
	MOVW	counter+32(FP), TMP
	MOVW	CTR, (TMP)
	
	RET

