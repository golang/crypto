// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding

import (
	"bytes"
	"io"
	"testing"
)

var mpiTests = []struct {
	encoded   []byte
	bytes     []byte
	reencoded []byte
	bitLength uint16
	err       error
}{
	{
		encoded:   []byte{0x0, 0x0},
		bytes:     []byte{},
		bitLength: 0,
	},
	{
		encoded:   []byte{0x0, 0x1, 0x1},
		bytes:     []byte{0x1},
		bitLength: 1,
	},
	{
		encoded:   []byte{0x0, 0x9, 0x1, 0xff},
		bytes:     []byte{0x1, 0xff},
		bitLength: 9,
	},
	{
		encoded:   append([]byte{0x1, 0x0, 0xff}, make([]byte, 0x1f)...),
		bytes:     append([]byte{0xff}, make([]byte, 0x1f)...),
		bitLength: 0x100,
	},
	// https://bugs.gnupg.org/gnupg/issue1853
	{
		encoded:   []byte{0x0, 0x10, 0x0, 0x1},
		bytes:     []byte{0x0, 0x1},
		reencoded: []byte{0x0, 0x1, 0x1},
		bitLength: 0x10,
	},
	// EOF error,
	{
		encoded: []byte{},
		err:     io.ErrUnexpectedEOF,
	},
	{
		encoded: []byte{0x1, 0x0, 0x0},
		err:     io.ErrUnexpectedEOF,
	},
}

func TestMPI(t *testing.T) {
	for i, test := range mpiTests {
		mpi := new(MPI)
		if _, err := mpi.ReadFrom(bytes.NewBuffer(test.encoded)); err != nil {
			if !sameError(err, test.err) {
				t.Errorf("#%d: ReadFrom error got:%q", i, err)
			}
			continue
		}
		if b := mpi.Bytes(); !bytes.Equal(b, test.bytes) {
			t.Errorf("#%d: bad creation got:%x want:%x", i, b, test.bytes)
		}
		if bl := mpi.BitLength(); bl != test.bitLength {
			t.Errorf("#%d: bad BitLength got:%d want:%d", i, bl, test.bitLength)
		}

		reencoded := test.encoded
		if test.reencoded != nil {
			reencoded = test.reencoded
		}

		if b := mpi.EncodedBytes(); !bytes.Equal(b, test.encoded) {
			t.Errorf("#%d: bad encoding got:%x want:%x", i, b, test.encoded)
		}
		if b := NewMPI(mpi.Bytes()).EncodedBytes(); !bytes.Equal(b, reencoded) {
			t.Errorf("#%d: bad encoding got:%x want:%x", i, b, reencoded)
		}
	}
}
