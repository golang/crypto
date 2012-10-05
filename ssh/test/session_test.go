// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !windows

package test

// Session functional tests.

import (
	"bytes"
	"io"
	"testing"
)

func TestRunCommandSuccess(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	conn := server.Dial()
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("session failed: %v", err)
	}
	defer session.Close()
	err = session.Run("true")
	if err != nil {
		t.Fatalf("session failed: %v", err)
	}
}

func TestRunCommandFailed(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	conn := server.Dial()
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("session failed: %v", err)
	}
	defer session.Close()
	err = session.Run(`bash -c "kill -9 $$"`)
	if err == nil {
		t.Fatalf("session succeeded: %v", err)
	}
}

func TestRunCommandWeClosed(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	conn := server.Dial()
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("session failed: %v", err)
	}
	err = session.Shell()
	if err != nil {
		t.Fatalf("shell failed: %v", err)
	}
	err = session.Close()
	if err != nil {
		t.Fatalf("shell failed: %v", err)
	}
}

func TestFuncLargeRead(t *testing.T) {
	server := newServer(t)
	defer server.Shutdown()
	conn := server.Dial()
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("unable to create new session: %s", err)
	}

	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("unable to acquire stdout pipe: %s", err)
	}

	err = session.Start("dd if=/dev/urandom bs=2048 count=1")
	if err != nil {
		t.Fatalf("unable to execute remote command: %s", err)
	}

	buf := new(bytes.Buffer)
	n, err := io.Copy(buf, stdout)
	if err != nil {
		t.Fatalf("error reading from remote stdout: %s", err)
	}

	if n != 2048 {
		t.Fatalf("Expected %d bytes but read only %d from remote command", 2048, n)
	}
}
