// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Ported from https://github.com/WireGuard/wireguard-monolithic-historical/blob/edad0d6e99e5133b1e8e865d727a25fff6399cb4/src/crypto/zinc/poly1305/poly1305-mips.S
// which is licensed under:
// # ====================================================================
// # SPDX-License-Identifier: GPL-2.0 OR MIT
// #
// # Copyright (C) 2016-2018 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
// # Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
// # ====================================================================

//go:build gc && !purego

#include "textflag.h"

#define MADDU(rs, rt) \
	WORD $(0x70000001 + (rs << 21) + (rt << 16));

#define ADDU_C(CA, D, H)\
	ADDU	CA, H 		\
	SGTU	CA, H, CA  	\
	ADDU	D, H  		\
	SGTU	D, H, D  	\
	ADDU	D, CA

#define ADDU_CA(CA, H) 	\
	ADDU	CA, H 		\
	SGTU	CA, H, CA

#define PTR_POLY1305_H(n) (n*4)(STATE)
#define PTR_POLY1305_R(n) ( 24 + (n*4))(STATE)

#define P_H0 	R1
#define P_H0_n 	1
#define P_H1 	R2
#define P_H1_n 	2
#define P_H2	R3
#define P_H2_n	3
#define P_H3 	R4
#define P_H3_n 	4
#define P_H4 	R5
#define P_H4_n 	5

#define P_R0 	R6
#define P_R0_n 	6
#define P_R1 	R7
#define P_R1_n 	7
#define P_R2 	R8
#define P_R2_n 	8
#define P_R3 	R9
#define P_R3_n 	9

#define P_S1 	R10
#define P_S1_n 	10
#define P_S2 	R11
#define P_S2_n 	11
#define P_S3 	R12
#define P_S3_n 	12

#define STATE	R13
#define MSG		R14
#define MSG_LEN	R15

#define D_0 	R16
#define D_1 	R17
#define D_2 	R18
#define D_3 	R19

#define CA		R20
#define CA_n	20
#define SC		R21
#define SC_n	21

#define TMP		R22

#define MSB 3
#define LSB 0

// func update(state *[7]uint64, msg []byte, padbit uint32)
TEXT ·update(SB), NOSPLIT|NOFRAME, $0
	MOVW state+0(FP), STATE
	MOVW D_base+4(FP), MSG
	MOVW D_len+8(FP), MSG_LEN

	/* load Rx */
	MOVW	PTR_POLY1305_R(0), P_R0
	MOVW	PTR_POLY1305_R(1), P_R1
	MOVW	PTR_POLY1305_R(2), P_R2
	MOVW	PTR_POLY1305_R(3), P_R3

	/* load Hx */
	MOVW	PTR_POLY1305_H(0), P_H0
	MOVW	PTR_POLY1305_H(1), P_H1
	MOVW	PTR_POLY1305_H(2), P_H2
	MOVW	PTR_POLY1305_H(3), P_H3
	MOVW	PTR_POLY1305_H(4), P_H4

	/* Sx = Rx + (Rx >> 2) */
	SRL		$2, P_R1, P_S1
	SRL		$2, P_R2, P_S2
	SRL		$2, P_R3, P_S3
	ADDU	P_R1, P_S1
	ADDU	P_R2, P_S2
	ADDU	P_R3, P_S3

	MOVW	$1, SC

	// The following code up to loop is needed to fix some tests:
	// - Override initial state to ensure large h (subject to h < 2(2¹³⁰ - 5)) is deserialized from the state correctly.
	//
	// For those tests we need to calc the modulus before starting, normally we do that at the end but there are tests
	// that come with a larger h.
	/* c = (h4 >> 2) + (h4 & ~3U); */
	SRL		$2, P_H4, CA
	SLL		$2, CA, TMP
	ADDU	TMP, CA
	/* h4 &= 3 */
	AND		$3,	P_H4

loop:
	MOVWL	 0+MSB(MSG), D_0
	MOVWL	 4+MSB(MSG), D_1
	MOVWL	 8+MSB(MSG), D_2
	MOVWL	12+MSB(MSG), D_3
	MOVWR	 0+LSB(MSG), D_0
	MOVWR	 4+LSB(MSG), D_1
	MOVWR	 8+LSB(MSG), D_2
	MOVWR	12+LSB(MSG), D_3

	/* h0 = (u32)(d0 = (u64)h0 + inp[0]); */
	ADDU_C	(CA, D_0, P_H0)
	
	/* h1 = (u32)(d1 = (u64)h1 + (d0 >> 32) + inp[4]); */
	ADDU_C	(CA, D_1, P_H1)

	/* h2 = (u32)(d2 = (u64)h2 + (d1 >> 32) + inp[8]); */
	ADDU_C	(CA, D_2, P_H2)

	/* h3 = (u32)(d3 = (u64)h3 + (d2 >> 32) + inp[12]); */
	ADDU_C	(CA, D_3, P_H3)

	/* h4 += (u32)(d3 >> 32) + padbit; */
	MOVW	padbit+16(FP), TMP
	ADDU	TMP, P_H4
	ADDU	CA, P_H4

	/* D0 */
	MULU	P_H0, P_R0
	MADDU	(P_H1_n, P_S3_n)
	MADDU	(P_H2_n, P_S2_n)
	MADDU	(P_H3_n, P_S1_n)
	MOVW	HI,	CA
	MOVW	LO, D_0

	/* D1 */
	MULU	P_H0, P_R1
	MADDU	(P_H1_n, P_R0_n)
	MADDU	(P_H2_n, P_S3_n)
	MADDU	(P_H3_n, P_S2_n)
	MADDU	(P_H4_n, P_S1_n)
	MADDU	(CA_n, SC_n)
	MOVW	HI, CA
	MOVW	LO, D_1

	/* D2 */
	MULU	P_H0, P_R2
	MADDU	(P_H1_n, P_R1_n)
	MADDU	(P_H2_n, P_R0_n)
	MADDU	(P_H3_n, P_S3_n)
	MADDU	(P_H4_n, P_S2_n)
	MADDU	(CA_n, SC_n)
	MOVW	HI, CA
	MOVW	LO, D_2

	/* D3 */
	MULU	P_H0, P_R3
	MADDU	(P_H1_n, P_R2_n)
	MADDU	(P_H2_n, P_R1_n)
	MADDU	(P_H3_n, P_R0_n)
	MADDU	(P_H4_n, P_S3_n)
	MADDU	(CA_n, SC_n)
	MOVW	HI, CA
	MOVW	LO, D_3

	/* D4 */
	MULU	P_H4, P_R0
	MADDU	(CA_n, SC_n)
	MOVW	LO, P_H4

	MOVW	D_0, P_H0
	MOVW	D_1, P_H1
	MOVW	D_2, P_H2
	MOVW	D_3, P_H3
	/* P_H4 has been directly assigned in D4 step */
	
	/* c = (h4 >> 2) + (h4 & ~3U); */
	SRL		$2, P_H4, CA
	SLL		$2, CA, TMP
	ADDU	TMP, CA

	/* h4 &= 3 */
	AND		$3,	P_H4

	/* decrement length */
	ADDU	$-16, MSG_LEN, MSG_LEN

	/* increment pointers */
	MOVW 	$16(MSG), MSG

	/* able to do a 16 byte block. */
	BNE     MSG_LEN, loop

	/* h += c; */
	ADDU_CA	(CA, P_H0)
	ADDU_CA	(CA, P_H1)
	ADDU_CA	(CA, P_H2)
	ADDU_CA	(CA, P_H3)
	ADDU_CA	(CA, P_H4)

	/* store Hx */
	MOVW	P_H0, PTR_POLY1305_H(0)
	MOVW	P_H1, PTR_POLY1305_H(1)
	MOVW	P_H2, PTR_POLY1305_H(2)
	MOVW	P_H3, PTR_POLY1305_H(3)
	MOVW	P_H4, PTR_POLY1305_H(4)
	MOVW	$0, PTR_POLY1305_H(5)

	RET
