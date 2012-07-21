// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	crypto_rand "crypto/rand"
	"io"
	"math/rand"
	"testing"
)

// windowTestBytes is the number of bytes that we'll send to the SSH server.
const windowTestBytes = 16000 * 200

// CopyNRandomly copies n bytes from src to dst. It uses a variable, and random,
// buffer size to exercise more code paths.
func CopyNRandomly(dst io.Writer, src io.Reader, n int) (written int, err error) {
	buf := make([]byte, 32*1024)
	for written < n {
		l := (rand.Intn(30) + 1) * 1024
		if d := n - written; d < l {
			l = d
		}
		nr, er := src.Read(buf[0:l])
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += nw
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			err = er
			break
		}
	}
	return written, err
}

func TestServerWindow(t *testing.T) {
	addr := startSSHServer(t)
	runSSHClient(t, addr)
}

// runSSHClient writes random data to the server. The server is expected to echo
// the same data back, which is compared against the original.
func runSSHClient(t *testing.T, addr string) {
	conn, err := Dial("tcp", addr, &ClientConfig{})
	if err != nil {
		t.Fatal(err)
	}

	session, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}

	origBuf := bytes.NewBuffer(make([]byte, 0, windowTestBytes))
	echoedBuf := bytes.NewBuffer(make([]byte, 0, windowTestBytes))
	io.CopyN(origBuf, crypto_rand.Reader, windowTestBytes)
	origBytes := origBuf.Bytes()

	wait := make(chan bool)

	// Read back the data from the server.
	go func() {
		defer session.Close()
		defer close(wait)
		serverStdout, err := session.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}

		n, err := CopyNRandomly(echoedBuf, serverStdout, windowTestBytes)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		if n != windowTestBytes {
			t.Fatalf("Read only %d bytes from server, expected %d", n, windowTestBytes)
		}
	}()

	serverStdin, err := session.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}

	written, err := CopyNRandomly(serverStdin, origBuf, windowTestBytes)
	if err != nil {
		t.Fatal(err)
	}
	if written != windowTestBytes {
		t.Fatalf("Wrote only %d of %d bytes to server", written, windowTestBytes)
	}

	<-wait

	if !bytes.Equal(origBytes, echoedBuf.Bytes()) {
		t.Error("Echoed buffer differed from original")
	}
}

func startSSHServer(t *testing.T) (addr string) {
	config := &ServerConfig{
		NoClientAuth: true,
	}

	err := config.SetRSAPrivateKey([]byte(testServerPrivateKey))
	if err != nil {
		t.Fatalf("Failed to parse private key: %s", err.Error())
	}

	listener, err := Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("Bind error: %s", err)
	}

	addr = listener.Addr().String()
	go func() {
		defer listener.Close()
		for {
			sConn, err := listener.Accept()
			err = sConn.Handshake()
			if err != nil {
				if err != io.EOF {
					t.Fatalf("failed to handshake: %s", err)
				}
				return
			}

			go connRun(t, sConn)
		}
	}()

	return
}

func connRun(t *testing.T, sConn *ServerConn) {
	defer sConn.Close()
	for {
		channel, err := sConn.Accept()
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("ServerConn.Accept failed: %s", err)
		}

		if channel.ChannelType() != "session" {
			channel.Reject(UnknownChannelType, "unknown channel type")
			continue
		}
		err = channel.Accept()
		if err != nil {
			t.Fatalf("Channel.Accept failed: %s", err)
		}

		go func() {
			defer channel.Close()
			n, err := CopyNRandomly(channel, channel, windowTestBytes)
			if err != nil && err != io.EOF {
				if err == io.ErrShortWrite {
					t.Fatalf("short write, wrote %d, expected %d", n, windowTestBytes)
				}
				t.Fatal(err)
			}
		}()
	}
}
