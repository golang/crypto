// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"
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

func TestClientImplementsDialContext(t *testing.T) {
	type ContextDialer interface {
		DialContext(context.Context, string, string) (net.Conn, error)
	}
	// Belt and suspenders assertion, since package net does not
	// declare a ContextDialer type.
	var _ ContextDialer = &net.Dialer{}
	var _ ContextDialer = &Client{}
}

func TestClientDialContextWithCancel(t *testing.T) {
	c := &Client{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := c.DialContext(ctx, "tcp", "localhost:1000")
	if err != context.Canceled {
		t.Errorf("DialContext: got nil error, expected %v", context.Canceled)
	}
}

func TestClientDialContextWithDeadline(t *testing.T) {
	c := &Client{}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now())
	defer cancel()
	_, err := c.DialContext(ctx, "tcp", "localhost:1000")
	if err != context.DeadlineExceeded {
		t.Errorf("DialContext: got nil error, expected %v", context.DeadlineExceeded)
	}
}

func TestDialNamedPort(t *testing.T) {
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
				if err := newChan.Reject(UnknownChannelType, "This test server only supports direct-tcpip"); err != nil {
					srvErr <- err
				}
				continue
			}
			data := channelOpenDirectMsg{}
			if err := Unmarshal(newChan.ExtraData(), &data); err != nil {
				if err := newChan.Reject(ConnectionFailed, err.Error()); err != nil {
					srvErr <- err
				}
				continue
			}
			// Below we dial for service `ssh` which should be translated to 22.
			if data.Port != 22 {
				if err := newChan.Reject(ConnectionFailed, fmt.Sprintf("expected port 22 got=%d", data.Port)); err != nil {
					srvErr <- err
				}
				continue
			}
			ch, reqs, err := newChan.Accept()
			if err != nil {
				srvErr <- fmt.Errorf("Accept: %w", err)
				continue
			}
			go DiscardRequests(reqs)
			if err := ch.Close(); err != nil {
				srvErr <- err
			}
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

	// The port section in the host:port string being a named service `ssh` is the main point of the test.
	_, err = sshClient.Dial("tcp", "localhost:ssh")
	if err != nil {
		t.Error(err)
	}

	// Stop the ssh server.
	clientConn.Close()
	for err := range srvErr {
		t.Errorf("ssh server: %s", err)
	}
}
