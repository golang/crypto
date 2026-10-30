// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27

package bundle

// subjectsEqual reports whether two RFC 2253 DN strings match.
//
// When testing with Go 1.27 or newer, it requires subjects to match exactly.
// When testing with Go 1.26, it tolerates the rendering difference introduced in Go 1.27,
// where string-typed attribute values for OIDs outside attributeTypeNames are rendered
// as strings rather than hex-encoded DER (see Go CL 773800).
//
// When Go 1.26 is no longer supported,
// the Go 1.26 version can be removed and
// the Go 1.27+ version can be inlined.
func subjectsEqual(a, b string) bool {
	return a == b
}
