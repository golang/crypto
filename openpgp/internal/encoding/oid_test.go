// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package encoding

import (
	"bytes"
	"io"
	"testing"

	"golang.org/x/crypto/openpgp/errors"
)

var oidTests = []struct {
	encoded   []byte
	bytes     []byte
	bitLength uint16
	err       error
}{
	{
		encoded:   []byte{0x1, 0x1},
		bytes:     []byte{0x1},
		bitLength: 8,
	},
	{
		encoded:   []byte{0x2, 0x1, 0x2},
		bytes:     []byte{0x1, 0x2},
		bitLength: 16,
	},
	{
		encoded:   []byte{0xa, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa},
		bytes:     []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa},
		bitLength: 80,
	},
	// extension overlap errors
	{
		encoded: []byte{0x0},
		err:     errors.UnsupportedError("reserved for future extensions"),
	},
	{
		encoded: append([]byte{0xff}, make([]byte, 0xff)...),
		err:     errors.UnsupportedError("reserved for future extensions"),
	},
	// EOF error,
	{
		encoded: []byte{},
		err:     io.ErrUnexpectedEOF,
	},
	{
		encoded: []byte{0xa},
		err:     io.ErrUnexpectedEOF,
	},
}

func TestOID(t *testing.T) {
	for i, test := range oidTests {
		oid := new(OID)
		if _, err := oid.ReadFrom(bytes.NewBuffer(test.encoded)); err != nil {
			if !sameError(err, test.err) {
				t.Errorf("#%d: ReadFrom error got:%q", i, err)
			}
			continue
		}
		if b := oid.Bytes(); !bytes.Equal(b, test.bytes) {
			t.Errorf("#%d: bad creation got:%x want:%x", i, b, test.bytes)
		}
		if bl := oid.BitLength(); bl != test.bitLength {
			t.Errorf("#%d: bad BitLength got:%d want:%d", i, bl, test.bitLength)
		}
		if b := oid.EncodedBytes(); !bytes.Equal(b, test.encoded) {
			t.Errorf("#%d: bad encoding got:%x want:%x", i, b, test.encoded)
		}
	}
}

func sameError(err1, err2 error) bool {
	switch {
	case err1 == err2:
		return true
	case err1 == nil, err2 == nil:
		return false
	default:
		return err1.Error() == err2.Error()
	}
}
