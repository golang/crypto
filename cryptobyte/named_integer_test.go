// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cryptobyte

import (
	"testing"

	"golang.org/x/crypto/cryptobyte/asn1"
)

func TestReadASN1NamedInteger(t *testing.T) {
	type signed int64
	type unsigned uint64
	type smallSigned int8
	type smallUnsigned uint8
	var i signed
	var u unsigned
	var si smallSigned
	var su smallUnsigned
	for _, test := range []struct {
		out   interface{}
		value int64
		ok    bool
	}{
		{&i, -1234, true},
		{&u, 1234, true},
		{&si, -128, true},
		{&su, 255, true},
		{&si, 128, false},
		{&su, 256, false},
		{&u, -1, false},
	} {
		b := NewBuilder(nil)
		b.AddASN1Int64(test.value)
		encoded, err := b.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		in := String(encoded)
		if ok := in.ReadASN1Integer(test.out); ok != test.ok {
			t.Errorf("ReadASN1Integer(%T), value %d = %v, want %v", test.out, test.value, ok, test.ok)
		}
	}
	if i != -1234 || u != 1234 || si != -128 || su != 255 {
		t.Errorf("decoded values = %d, %d, %d, %d", i, u, si, su)
	}
}

func TestReadOptionalASN1NamedInteger(t *testing.T) {
	type integer int64
	const tag = asn1.SEQUENCE
	var out integer
	var empty String
	if !empty.ReadOptionalASN1Integer(&out, tag, integer(42)) || out != 42 {
		t.Fatalf("missing optional integer = %d, want 42", out)
	}
	b := NewBuilder(nil)
	b.AddASN1(tag, func(b *Builder) { b.AddASN1Int64(-1234) })
	encoded, err := b.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	in := String(encoded)
	if !in.ReadOptionalASN1Integer(&out, tag, integer(42)) || out != -1234 || !in.Empty() {
		t.Errorf("present optional integer = %d, want -1234", out)
	}
}
