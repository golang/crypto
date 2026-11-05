// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package bcrypt

import "encoding/base64"

const alphabet = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

var bcEncoding = base64.NewEncoding(alphabet).WithPadding(base64.NoPadding)

func base64Encode(src []byte) []byte {
	dst := make([]byte, bcEncoding.EncodedLen(len(src)))
	bcEncoding.Encode(dst, src)
	return dst
}

func base64Decode(src []byte) ([]byte, error) {
	dst := make([]byte, bcEncoding.DecodedLen(len(src)))
	_, err := bcEncoding.Decode(dst, src)
	if err != nil {
		return nil, err
	}
	return dst, nil
}
