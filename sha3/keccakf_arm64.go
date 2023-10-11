// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build arm64
// +build arm64

package sha3

// This function is implemented in keccakf_arm64.s.
// For ARMv8 machines GOARM=n/a, and GOARCH=arm64
// see  https://go.dev/wiki/GoArm
//go:noescape
func keccakF1600NEON(a *[25]uint64)

func keccakF1600(a *[25]uint64) {
	// FIXME: use "golang.org/x/sys/cpu" to check if the running machine has SHA3 feature.
	keccakF1600NEON(a)
}
