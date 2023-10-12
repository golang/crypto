// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"fmt"
	"testing"
)

func TestAutoPortListenBroken(t *testing.T) {
	broken := "SSH-2.0-OpenSSH_5.9hh11"
	works := "SSH-2.0-OpenSSH_6.1"
	if !isBrokenOpenSSHVersion(broken) {
		t.Errorf("version %q not marked as broken", broken)
	}
	if isBrokenOpenSSHVersion(works) {
		t.Errorf("version %q marked as broken", works)
	}
}

func TestDialNamedPort(t *testing.T) {
	// Test that sshClient.Dial supports named ports.

	srvConn, clientConn, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer srvConn.Close()
	defer clientConn.Close()

	serverConf := &ServerConfig{
		NoClientAuth: true,
	}
	serverConf.AddHostKey(testSigners["rsa"])
	srvErr := make(chan error, 10)
	go func() {
		defer close(srvErr)
		_, chans, req, err := NewServerConn(srvConn, serverConf)
		if err != nil {
			srvErr <- fmt.Errorf("NewServerConn: %w", err)
			return
		}
		go DiscardRequests(req)
		for newChan := range chans {
			if newChan.ChannelType() != "direct-tcpip" {
				srvErr <- fmt.Errorf("expected direct-tcpip channel, got=%s", newChan.ChannelType())
			}
			data := channelOpenDirectMsg{}
			if err := Unmarshal(newChan.ExtraData(), &data); err != nil {
				srvErr <- err
			}
			// Below we dial for service `ssh` which should be translated to 22.
			if data.Port != 22 {
				srvErr <- fmt.Errorf("expected port 22 got=%d", data.Port)
			}
			ch, reqs, err := newChan.Accept()
			if err != nil {
				srvErr <- fmt.Errorf("Accept: %w", err)
			}
			go DiscardRequests(reqs)
			ch.Close()
		}
	}()

	clientConf := &ClientConfig{
		User:            "testuser",
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	sshClientConn, newChans, reqs, err := NewClientConn(clientConn, "", clientConf)
	if err != nil {
		t.Fatal(err)
	}
	sshClient := NewClient(sshClientConn, newChans, reqs)

	// port being a named port `ssh` is the main point of the test.
	tcpipconn, err := sshClient.Dial("tcp", "localhost:ssh")
	if err != nil {
		t.Fatal(err)
	}
	tcpipconn.Close()

	clientConn.Close()

	for err := range srvErr {
		t.Errorf("ssh server: %s", err)
	}
}
