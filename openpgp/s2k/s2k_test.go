// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package s2k

import (
	"bytes"
	"crypto"
	_ "crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/hex"
	"testing"

	_ "golang.org/x/crypto/ripemd160"
)

var saltedTests = []struct {
	in, out string
}{
	{"hello", "10295ac1"},
	{"world", "ac587a5e"},
	{"foo", "4dda8077"},
	{"bar", "bd8aac6b9ea9cae04eae6a91c6133b58b5d9a61c14f355516ed9370456"},
	{"x", "f1d3f289"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "e00d7b45"},
}

func TestSalted(t *testing.T) {
	h := sha1.New()
	salt := [4]byte{1, 2, 3, 4}

	for i, test := range saltedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Salted(out, h, []byte(test.in), salt[:])
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

var iteratedTests = []struct {
	in, out string
}{
	{"hello", "83126105"},
	{"world", "6fa317f9"},
	{"foo", "8fbc35b9"},
	{"bar", "2af5a99b54f093789fd657f19bd245af7604d0f6ae06f66602a46a08ae"},
	{"x", "5a684dfe"},
	{"xxxxxxxxxxxxxxxxxxxxxxx", "18955174"},
}

func TestIterated(t *testing.T) {
	h := sha1.New()
	salt := [4]byte{4, 3, 2, 1}

	for i, test := range iteratedTests {
		expected, _ := hex.DecodeString(test.out)
		out := make([]byte, len(expected))
		Iterated(out, h, []byte(test.in), salt[:], 31)
		if !bytes.Equal(expected, out) {
			t.Errorf("#%d, got: %x want: %x", i, out, expected)
		}
	}
}

var parseTests = []struct {
	spec, in, out string
	dummyKey bool
	params Params
}{
	/* Simple with SHA1 */
	{"0002", "hello", "aaf4c61d", false,
		Params{0, 0x02, nil, 0}},
	/* Salted with SHA1 */
	{"01020102030405060708", "hello", "f4f7d67e", false,
		Params{1, 0x02, []byte{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, 0}},
	/* Iterated with SHA1 */
	{"03020102030405060708f1", "hello", "f2a57b7c", false,
		Params{3, 0x02, []byte{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 }, 0xf1}},
	/* GNU dummy S2K */
	{"6502474e5501", "", "", true,
		Params{101, 0x02, nil, 0}},
}

func TestParseIntoParams(t *testing.T) {
	for i, test := range parseTests {
		spec, _ := hex.DecodeString(test.spec)
		buf := bytes.NewBuffer(spec)
		params, err := ParseIntoParams(buf)
		if err != nil {
			t.Errorf("%d: ParseIntoParams returned error: %s", i, err)
			continue
		}

		if test.params.mode != params.mode || test.params.hashId != params.hashId || test.params.countByte != params.countByte ||
			!bytes.Equal(test.params.salt, params.salt) {
			t.Errorf("%d: Wrong s2kconfig, got: %+v want: %+v", i, params, test.params)
		}

		if params.Dummy() != test.dummyKey {
			t.Errorf("%d: Got GNU dummy %v, expected %v", i, params.Dummy(), test.dummyKey)
		}

		if !test.dummyKey {
			expectedHash, _ := hex.DecodeString(test.out)
			out := make([]byte, len(expectedHash))

			f, err := params.Function()
			if err != nil {
				t.Errorf("%d: params.Function() returned error: %s", i, err)
				continue
			}
			f(out, []byte(test.in))
			if !bytes.Equal(out, expectedHash) {
				t.Errorf("%d: Wrong output got: %x want: %x", i, out, expectedHash)
			}
		}

		var reserialized bytes.Buffer
		err = params.Serialize(&reserialized)
		if err != nil {
			t.Errorf("%d: params.Serialize() returned error: %s", i, err)
			continue
		}
		if !bytes.Equal(reserialized.Bytes(), spec) {
			t.Errorf("%d: Wrong reserialized got: %x want: %x", i, reserialized.Bytes(), spec)
		}
		if testing.Short() {
			break
		}
	}
}

func TestSerialize(t *testing.T) {
	hashes := []crypto.Hash{crypto.MD5, crypto.SHA1, crypto.RIPEMD160,
		crypto.SHA256, crypto.SHA384, crypto.SHA512, crypto.SHA224}
	testCounts := []int{-1, 0, 1024, 65536, 4063232, 65011712}
	for _, h := range hashes {
		for _, c := range testCounts {
			testSerializeConfig(t, &Config{Hash: h, S2KCount: c})
		}
	}
}

func testSerializeConfig(t *testing.T, c *Config) {
	t.Logf("Running testSerializeConfig() with config: %+v", c)

	buf := bytes.NewBuffer(nil)
	key := make([]byte, 16)
	passphrase := []byte("testing")
	err := Serialize(buf, key, rand.Reader, passphrase, c)
	if err != nil {
		t.Errorf("failed to serialize: %s", err)
		return
	}

	f, err := Parse(buf)
	if err != nil {
		t.Errorf("failed to reparse: %s", err)
		return
	}
	key2 := make([]byte, len(key))
	f(key2, passphrase)
	if !bytes.Equal(key2, key) {
		t.Errorf("keys don't match: %x (serialied) vs %x (parsed)", key, key2)
	}
}
