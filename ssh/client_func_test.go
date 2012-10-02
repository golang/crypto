// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// ClientConn functional tests.
// These tests require a running ssh server listening on port 22
// on the local host. Functional tests will be skipped unless
// -ssh.user and -ssh.pass must be passed to gotest.

import (
	"bytes"
	"flag"
	"io"
	"testing"
)

var (
	sshuser    = flag.String("ssh.user", "", "ssh username")
	sshpass    = flag.String("ssh.pass", "", "ssh password")
	sshprivkey = flag.String("ssh.privkey", "", "ssh privkey file")
)

func TestFuncPasswordAuth(t *testing.T) {
	if *sshuser == "" {
		t.Log("ssh.user not defined, skipping test")
		return
	}
	config := &ClientConfig{
		User: *sshuser,
		Auth: []ClientAuth{
			ClientAuthPassword(password(*sshpass)),
		},
	}
	conn, err := Dial("tcp", "localhost:22", config)
	if err != nil {
		t.Fatalf("Unable to connect: %s", err)
	}
	defer conn.Close()
}

func TestFuncPublickeyAuth(t *testing.T) {
	if *sshuser == "" {
		t.Log("ssh.user not defined, skipping test")
		return
	}
	kc := new(keychain)
	if err := kc.loadPEM(*sshprivkey); err != nil {
		t.Fatalf("unable to load private key: %s", err)
	}
	config := &ClientConfig{
		User: *sshuser,
		Auth: []ClientAuth{
			ClientAuthKeyring(kc),
		},
	}
	conn, err := Dial("tcp", "localhost:22", config)
	if err != nil {
		t.Fatalf("unable to connect: %s", err)
	}
	defer conn.Close()
}

func TestFuncLargeRead(t *testing.T) {
	if *sshuser == "" {
		t.Log("ssh.user not defined, skipping test")
		return
	}
	kc := new(keychain)
	if err := kc.loadPEM(*sshprivkey); err != nil {
		t.Fatalf("unable to load private key: %s", err)
	}
	config := &ClientConfig{
		User: *sshuser,
		Auth: []ClientAuth{
			ClientAuthKeyring(kc),
		},
	}
	conn, err := Dial("tcp", "localhost:22", config)
	if err != nil {
		t.Fatalf("unable to connect: %s", err)
	}
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
