// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"context"
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

func TestClientDialContextWithTimeout(t *testing.T) {
	c := &Client{}
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	_, err := c.DialContext(ctx, "tcp", "localhost:1000")
	if err != context.DeadlineExceeded {
		t.Errorf("DialContext: got nil error, expected %v", context.DeadlineExceeded)
	}
}
