// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"testing"
)

// TestChannelUnexpectedDefaultMessagesDiscarded is the default-arm counterpart
// of TestChannelUnexpectedResponsesDiscarded. A peer that spams messages which
// fall through to the default arm of (*channel).handlePacket — e.g. a
// service-request packet routed to a channel id — must not be able to fill
// ch.msg on an open, idle channel and stall the single mux read loop.
func TestChannelUnexpectedDefaultMessagesDiscarded(t *testing.T) {
	clientMux, serverMux := muxPair()
	defer serverMux.Close()
	defer clientMux.Close()

	serverRes := make(chan *channel, 1)
	go func() {
		newCh, ok := <-serverMux.incomingChannels
		if !ok {
			close(serverRes)
			return
		}
		c, _, err := newCh.Accept()
		if err != nil {
			close(serverRes)
			return
		}
		serverRes <- c.(*channel)
	}()

	clientCh, err := clientMux.openChannel("chan", nil)
	if err != nil {
		t.Fatalf("openChannel: %v", err)
	}
	serverCh := <-serverRes
	if serverCh == nil {
		t.Fatal("server did not accept channel")
	}

	// Craft a packet that the client mux routes to clientCh (the channel id is
	// read from packet[1:5]) and that decode() turns into a *serviceRequestMsg,
	// hitting the default arm of handlePacket. For a serviceRequestMsg the bytes
	// after the type byte are a length-prefixed string, so packet[1:5] (the
	// string length) doubles as the routed channel id.
	targetID := serverCh.remoteId // == clientCh.localId
	pkt := []byte{msgServiceRequest}
	pkt = binary.BigEndian.AppendUint32(pkt, targetID)
	pkt = append(pkt, make([]byte, targetID)...)

	// More than chanSize so ch.msg would overflow without the default-arm drop.
	const spam = chanSize * 4
	done := make(chan error, 1)
	go func() {
		for i := 0; i < spam; i++ {
			if err := serverMux.conn.writePacket(pkt); err != nil {
				done <- fmt.Errorf("writePacket %d: %w", i, err)
				return
			}
		}
		// Echo any legitimate request back.
		for req := range serverCh.incomingRequests {
			if req.WantReply {
				if err := req.Reply(true, append([]byte("reply:"), req.Payload...)); err != nil {
					done <- fmt.Errorf("reply: %w", err)
					return
				}
			}
		}
		done <- nil
	}()

	// If the flood had wedged the client mux read loop, this SendRequest would
	// never receive a reply.
	ok, err := clientCh.SendRequest("ping", true, []byte("hello"))
	if err != nil {
		t.Fatalf("SendRequest: %v", err)
	}
	if !ok {
		t.Fatal("expected success reply")
	}

	clientCh.Close()
	serverCh.Close()
	if err := <-done; err != nil {
		if !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
}
