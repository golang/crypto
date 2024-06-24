// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !go1.19

package sha3

import _ "unsafe" // for go:linkname

//go:linkname xorBytes crypto/cipher.xorBytes
//go:noescape
func xorBytes(dst, a, b []byte)
