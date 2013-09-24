// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// Key exchange tests.

import (
	"crypto/rand"
	"io"
	"reflect"
	"testing"
)

// An in-memory packetConn.
type memTransport struct {
	r, w chan []byte
}

func (t *memTransport) readPacket() ([]byte, error) {
	p, ok := <-t.r
	if !ok {
		return nil, io.EOF
	}

	return p, nil
}

func (t *memTransport) Close() error {
	close(t.w)
	return nil
}

func (t *memTransport) writePacket(p []byte) error {
	t.w <- p
	return nil
}

func memPipe() (a, b packetConn) {
	p := make(chan []byte, 1)
	q := make(chan []byte, 1)
	return &memTransport{p, q}, &memTransport{q, p}
}

func TestKexes(t *testing.T) {
	type kexResultErr struct {
		result *kexResult
		err    error
	}

	for name, kex := range kexAlgoMap {
		a, b := memPipe()

		s := make(chan kexResultErr, 1)
		c := make(chan kexResultErr, 1)
		var magics handshakeMagics
		go func() {
			r, e := kex.Client(a, rand.Reader, &magics)
			c <- kexResultErr{r, e}
		}()
		go func() {
			r, e := kex.Server(b, rand.Reader, &magics, ecdsaKey)
			s <- kexResultErr{r, e}
		}()

		clientRes := <-c
		serverRes := <-s
		if clientRes.err != nil {
			t.Errorf("client: %v", clientRes.err)
		}
		if serverRes.err != nil {
			t.Errorf("server: %v", serverRes.err)
		}
		if !reflect.DeepEqual(clientRes.result, serverRes.result) {
			t.Errorf("kex %q: mismatch %#v, %#v", name, clientRes.result, serverRes.result)
		}
	}
}
