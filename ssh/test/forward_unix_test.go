// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd linux netbsd openbsd

package test

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"testing"
)

func TestPortForward(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	conn := server.Dial(clientConfig())
	defer conn.Close()

	var sshListener net.Listener
	var err error
	tries := 10
	for i := 0; i < tries; i++ {
		port := 1024 + rand.Intn(50000)

		// We can't reliably test dynamic port allocation, as it does
		// not work correctly with OpenSSH before 6.0. See also
		// https://bugzilla.mindrot.org/show_bug.cgi?id=2017
		sshListener, err = conn.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
	}

	if err != nil {
		t.Fatalf("conn.Listen failed: %v (after %d tries)", err, tries)
	}

	go func() {
		sshConn, err := sshListener.Accept()
		if err != nil {
			t.Fatalf("listen.Accept failed: %v", err)
		}

		_, err = io.Copy(sshConn, sshConn)
		if err != nil && err != io.EOF {
			t.Fatalf("ssh client copy: %v", err)
		}
		sshConn.Close()
	}()

	forwardedAddr := sshListener.Addr().String()
	tcpConn, err := net.Dial("tcp", forwardedAddr)
	if err != nil {
		t.Fatalf("TCP dial failed: %v", err)
	}

	readChan := make(chan []byte)
	go func() {
		data, _ := ioutil.ReadAll(tcpConn)
		readChan <- data
	}()

	// Invent some data.
	data := make([]byte, 100*1000)
	for i := range data {
		data[i] = byte(i % 255)
	}

	var sent []byte
	for len(sent) < 1000*1000 {
		// Send random sized chunks
		m := rand.Intn(len(data))
		n, err := tcpConn.Write(data[:m])
		if err != nil {
			break
		}
		sent = append(sent, data[:n]...)
	}
	if err := tcpConn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Errorf("tcpConn.CloseWrite: %v", err)
	}

	read := <-readChan

	if len(sent) != len(read) {
		t.Fatalf("got %d bytes, want %d", len(read), len(sent))
	}
	if bytes.Compare(sent, read) != 0 {
		t.Fatalf("read back data does not match")
	}

	if err := sshListener.Close(); err != nil {
		t.Fatalf("sshListener.Close: %v", err)
	}

	// Check that the forward disappeared.
	tcpConn, err = net.Dial("tcp", forwardedAddr)
	if err == nil {
		tcpConn.Close()
		t.Errorf("still listening to %s after closing", forwardedAddr)
	}
}
