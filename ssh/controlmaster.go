// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// controlMasterMessage covers multiple CM packets that have no data
type controlMasterMessage struct {
	PacketType uint32 // MUX_C_ALIVE_CHECK|MUX_C_PROXY|MUX_S_PROXY|MUX_S_OK
	RequestID  uint32
}

// controlMasterAliveMessage is a response to a MUX_C_ALIVE_CHECK request
type controlMasterAliveMessage struct {
	PacketType uint32 // MUX_S_ALIVE
	RequestID  uint32
	ServerPID  uint32
}

// controlMasterHelloMessage is used to ask/send the protocol version
type controlMasterHelloMessage struct {
	PacketType      uint32 // MUX_MSG_HELLO
	ProtocolVersion uint32
}

// DialControlMaster starts a client connection to the given SSH server.
// It is a convenience function that connects to the given unix socket,
// initiates the ControlMaster proxy prottocol, and then sets up a Client.
// For access to incoming channels and requests, use net.Dial with
// NewControlMasterClientConn instead.
func DialControlMaster(path string) (*Client, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := NewControlMasterClientConn(conn)
	if err != nil {
		return nil, err
	}
	return NewClient(c, chans, reqs), nil
}

// NewControlMasterClientConn establishes a ControlMaster connection
// using c as the underlying transport. The Request and NewChannel
// channels must be serviced or the connection will hang.
func NewControlMasterClientConn(c net.Conn) (Conn, <-chan NewChannel, <-chan *Request, error) {
	// We never populate transport, just mux since there is no handshake needed
	conn := &connection{
		sshConn: sshConn{conn: c},
	}

	// Instead of calling clientHandshake, call our own setup function
	if err := setupControlMaster(&controlMasterConnection{
		rw: c,
	}); err != nil {
		return nil, nil, nil, err
	}

	// Instead of using transport we use our own impl packetConn instead
	conn.mux = newMux(&controlMasterProxyConnection{
		rwc: c,
	})
	return conn, conn.mux.incomingChannels, conn.mux.incomingRequests, nil
}

// controlMasterConnection implements the control master protocol
type controlMasterConnection struct {
	rw io.ReadWriter
}

// writePacket prefixes the length to the packet and writes it
func (c *controlMasterConnection) writePacket(packet interface{}) error {
	// Marshal the packet as standard SSH packets
	msg := Marshal(packet)
	// We need to calculate the length field
	msgLenBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(msgLenBytes, uint32(len(msg)))
	msg = append(msgLenBytes, msg...)
	n, err := c.rw.Write(msg)
	if err != nil {
		return err
	}
	if n != len(msg) {
		return errors.New("Unable to write all bytes in message")
	}
	return nil
}

// readPacket reads a packet based on an initial length value
func (c *controlMasterConnection) readPacket(packet interface{}) error {
	// Read the response length
	respLenBuf := make([]byte, 4)
	n1, err := c.rw.Read(respLenBuf)
	if err != nil {
		return err
	}
	if n1 != 4 {
		return errors.New("Unable to read entire response packet length")
	}
	respLen := binary.BigEndian.Uint32(respLenBuf)
	// Then read the response
	resp := make([]byte, respLen)
	n2, err := c.rw.Read(resp)
	if err != nil {
		return err
	}
	if uint32(n2) != respLen {
		return errors.New("Unable to read entire response packet")
	}
	if err := Unmarshal(resp, packet); err != nil {
		return err
	}
	return nil
}

// setupControlMaster gets a CM session setup and switches to proxy mode
func setupControlMaster(c *controlMasterConnection) error {
	// Write our own hello with version
	if err := c.writePacket(&controlMasterHelloMessage{
		// MUX_MSG_HELLO
		PacketType:      0x00000001,
		ProtocolVersion: 4,
	}); err != nil {
		return err
	}
	// Read the hello message
	var hello controlMasterHelloMessage
	if err := c.readPacket(&hello); err != nil {
		return err
	}
	// MUX_MSG_HELLO
	if hello.PacketType != 0x00000001 {
		return errors.New("Unknown PacketType, expecting MUX_MSG_HELLO")
	}
	// Check that the server sent a protocol we know
	if hello.ProtocolVersion != 4 {
		return errors.New("Unknown ControlMaster protocol")
	}
	// Send an alive check with request id 1
	if err := c.writePacket(&controlMasterMessage{
		// MUX_C_ALIVE_CHECK
		PacketType: 0x10000004,
		RequestID:  1,
	}); err != nil {
		return err
	}
	// Read the alive check response message
	var alive controlMasterAliveMessage
	if err := c.readPacket(&alive); err != nil {
		return err
	}
	// MUX_S_ALIVE
	if alive.PacketType != 0x80000005 {
		return errors.New("Unknown PacketType, expecting MUX_C_ALIVE_CHECK")
	}
	// Request that we move to proxy mode with request id 2
	if err := c.writePacket(&controlMasterMessage{
		// MUX_C_PROXY
		PacketType: 0x1000000F,
		RequestID:  2,
	}); err != nil {
		return err
	}
	// Wait for confirmation we are now in proxy mode
	var proxy controlMasterMessage
	if err := c.readPacket(&proxy); err != nil {
		return err
	}
	// MUX_S_PROXY
	if proxy.PacketType != 0x8000000F {
		return errors.New("Unknown PacketType, expecting MUX_S_PROXY")
	}
	return nil
}

// controlMasterProxyConnection implements the controlmaster proxy protocol
type controlMasterProxyConnection struct {
	rwc io.ReadWriteCloser
}

// writePacket prefixes the length and a 0 byte of padding
func (c *controlMasterProxyConnection) writePacket(packet []byte) error {
	// Packet length is the length of data plus 1 byte of padding
	packetLen := uint32(len(packet) + 1)
	msgLenBytes := make([]byte, 5)
	binary.BigEndian.PutUint32(msgLenBytes[0:4], packetLen)
	packet = append(msgLenBytes, packet...)
	n, err := c.rwc.Write(packet)
	if err != nil {
		return err
	}
	if n != len(packet) {
		return errors.New("Unable to write all bytes in proxy packet")
	}
	return nil
}

// readPacket reads a packet based on an initial length value minus padding
func (c *controlMasterProxyConnection) readPacket() ([]byte, error) {
	// 4 bytes of length
	header := make([]byte, 4)
	n1, err := c.rwc.Read(header)
	if err != nil {
		return nil, err
	}
	if n1 != 4 {
		return nil, errors.New("Unable to read entire proxy response packet length")
	}
	respLen := binary.BigEndian.Uint32(header)
	// Then read the response packet
	resp := make([]byte, respLen)
	n2, err := c.rwc.Read(resp)
	if err != nil {
		return nil, err
	}
	if uint32(n2) != respLen {
		return nil, errors.New("Unable to read entire proxy response packet")
	}
	// There is 1 byte of padding at the start
	return resp[1:], nil
}

// Close just passes through to the underlying io.ReadWriteCloser
func (c *controlMasterProxyConnection) Close() error {
	return c.rwc.Close()
}
