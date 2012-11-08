// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// We have a implementation in amd64 assembly so this code is only run on
// non-amd64 platforms.  The amd64 assembly does not support gccgo.
// +build !amd64 gccgo

package curve25519

import (
	"math/big"
)

// p is the prime order of the underlying field: 2^255-19
var p *big.Int

// pMinus2 is p-2
var pMinus2 *big.Int

// a is a parameter of the elliptic curve: 486662
var a *big.Int

func init() {
	p, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed", 16)
	pMinus2, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb", 16)
	a = new(big.Int).SetInt64(486662)
}

// context contains state shared throughout the computation, including scratch
// variables to save on allocation.
type context struct {
	tmp1, tmp2, tmp3, tmp4 *big.Int
	x1                     *big.Int
}

// add sets (outx, outz) to the sum of two points in the elliptic curve group.
// See http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#diffadd-dadd-1987-m
// outx and outz should not alias any of the other inputs.
func (c *context) add(outx, outz, xn, zn, xm, zm *big.Int) {
	// x₃ = 4(x·x′ - z·z′)² · z1
	// (z1 == 1 here)
	c.tmp1.Mul(xn, xm)
	c.tmp2.Mul(zn, zm)
	c.tmp3.Sub(c.tmp1, c.tmp2)
	outx.Mul(c.tmp3, c.tmp3)
	outx.Lsh(outx, 2)
	outx.Mod(outx, p)

	// z₃ = 4(x·z′ - z·x′)² · x1
	// (x1 == 1 here)
	c.tmp1.Mul(xm, zn)
	c.tmp2.Mul(zm, xn)
	c.tmp3.Sub(c.tmp1, c.tmp2)
	outz.Mul(c.tmp3, c.tmp3)
	outz.Mul(outz, c.x1)
	outz.Lsh(outz, 2)
	outz.Mod(outz, p)

	return
}

// double sets (outx, outz) to 2*(x,z) in the elliptic curve group. See
// http://hyperelliptic.org/EFD/g1p/auto-montgom-xz.html#doubling-dbl-1987-m
// outx and outz should not alias any of the other inputs.
func (c *context) double(outx, outz, x, z *big.Int) {
	// x₂ = (x² - z²)²
	c.tmp1.Mul(x, x)
	c.tmp2.Mul(z, z)
	c.tmp3.Sub(c.tmp1, c.tmp2)
	outx.Mul(c.tmp3, c.tmp3)
	outx.Mod(outx, p)

	// z₂ = 4xz·(x² + Axz + z²)
	c.tmp3.Add(c.tmp1, c.tmp2)
	c.tmp1.Mul(x, z)
	c.tmp2.Mul(c.tmp1, a)
	outz.Add(c.tmp3, c.tmp2)
	c.tmp2.Lsh(c.tmp1, 2)
	outz.Mul(outz, c.tmp2)
	outz.Mod(outz, p)

	return
}

func scalarMult(out, in, base *[32]byte) {
	var baseReversed, inCopy [32]byte
	for i := 0; i < 32; i++ {
		baseReversed[31-i] = base[i]
		inCopy[i] = in[i]
	}

	inCopy[31] &= 127
	inCopy[31] |= 64
	inCopy[0] &= 248

	c := &context{new(big.Int), new(big.Int), new(big.Int), new(big.Int), nil}
	c.x1 = new(big.Int).SetBytes(baseReversed[:])

	x1 := new(big.Int).SetInt64(1)
	z1 := new(big.Int)
	x2 := new(big.Int).Set(c.x1)
	z2 := new(big.Int).SetInt64(1)
	outx := new(big.Int)
	outz := new(big.Int)

	for i := 0; i < 32; i++ {
		b := inCopy[31-i]
		for j := 0; j < 8; j++ {
			if b&0x80 != 0 {
				c.add(outx, outz, x1, z1, x2, z2)
				x1, z1, outx, outz = outx, outz, x1, z1
				c.double(outx, outz, x2, z2)
				x2, z2, outx, outz = outx, outz, x2, z2
			} else {
				c.add(outx, outz, x1, z1, x2, z2)
				x2, z2, outx, outz = outx, outz, x2, z2
				c.double(outx, outz, x1, z1)
				x1, z1, outx, outz = outx, outz, x1, z1
			}
			b <<= 1
		}
	}

	c.tmp1.Exp(z1, pMinus2, p)
	c.tmp2.Mul(x1, c.tmp1)
	c.tmp3.Mod(c.tmp2, p)

	outReversed := c.tmp3.Bytes()
	for i := 0; i < len(outReversed); i++ {
		out[i] = outReversed[len(outReversed)-(1+i)]
	}
	for i := len(outReversed); i < 32; i++ {
		out[i] = 0
	}
}
