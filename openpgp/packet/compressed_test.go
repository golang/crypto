// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package packet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"io/ioutil"
	mathrand "math/rand"
	"testing"
)

const (
	maxMessageLen = 1 << 12
)

func TestCompressed(t *testing.T) {
	packet, err := Read(readerFromHex(compressedHex))
	if err != nil {
		t.Errorf("failed to read Compressed: %s", err)
		return
	}

	c, ok := packet.(*Compressed)
	if !ok {
		t.Error("didn't find Compressed packet")
		return
	}

	contents, err := ioutil.ReadAll(c.Body)
	if err != nil && err != io.EOF {
		t.Error(err)
		return
	}

	expected, _ := hex.DecodeString(compressedExpectedHex)
	if !bytes.Equal(expected, contents) {
		t.Errorf("got:%x want:%x", contents, expected)
	}
}

const compressedHex = "a3013b2d90c4e02b72e25f727e5e496a5e49b11e1700"
const compressedExpectedHex = "cb1062004d14c8fe636f6e74656e74732e0a"

func TestCompressDecompressRandomizeFast(t *testing.T) {
	algorithms := []CompressionAlgo{
		CompressionZIP,
		CompressionZLIB,
	}
	plaintext := make([]byte, mathrand.Intn(maxMessageLen))
	rand.Read(plaintext)
	algo := algorithms[mathrand.Intn(len(algorithms))]
	compConfig := &CompressionConfig{
		Level: -1 + mathrand.Intn(11),
	}
	w := bytes.NewBuffer(nil)
	wc := &noOpCloser{w: w}
	wcomp, err := SerializeCompressed(wc, algo, compConfig)
	if err != nil {
		t.Fatal(err)
	}
	// Compress to w
	wcomp.Write(plaintext)
	wcomp.Close()
	// Read the packet and decompress
	p, err := Read(w)
	c, ok := p.(*Compressed)
	if !ok {
		t.Error("didn't find Compressed packet")
	}
	contents, err := ioutil.ReadAll(c.Body)
	if err != nil && err != io.EOF {
		t.Error(err)
	}
	if !bytes.Equal(contents, plaintext) {
		t.Error("Could not retrieve original after decompress")
	}
}
