// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"io"
	"sync"
)

// extendedDataTypeCode identifies an OpenSSL extended data type. See RFC 4254,
// section 5.2.
type extendedDataTypeCode uint32

// extendedDataStderr is the extended data type that is used for stderr.
const extendedDataStderr extendedDataTypeCode = 1

// A Channel is an ordered, reliable, duplex stream that is multiplexed over an
// SSH connection. Channel.Read can return a ChannelRequest as an error.
type Channel interface {
	// Accept accepts the channel creation request.
	Accept() error
	// Reject rejects the channel creation request. After calling this, no
	// other methods on the Channel may be called. If they are then the
	// peer is likely to signal a protocol error and drop the connection.
	Reject(reason RejectionReason, message string) error

	// Read may return a ChannelRequest as an error.
	Read(data []byte) (int, error)
	Write(data []byte) (int, error)
	Close() error

	// Stderr returns an io.Writer that writes to this channel with the
	// extended data type set to stderr.
	Stderr() io.Writer

	// AckRequest either sends an ack or nack to the channel request.
	AckRequest(ok bool) error

	// ChannelType returns the type of the channel, as supplied by the
	// client.
	ChannelType() string
	// ExtraData returns the arbitary payload for this channel, as supplied
	// by the client. This data is specific to the channel type.
	ExtraData() []byte
}

// ChannelRequest represents a request sent on a channel, outside of the normal
// stream of bytes. It may result from calling Read on a Channel.
type ChannelRequest struct {
	Request   string
	WantReply bool
	Payload   []byte
}

func (c ChannelRequest) Error() string {
	return "ssh: channel request received"
}

// RejectionReason is an enumeration used when rejecting channel creation
// requests. See RFC 4254, section 5.1.
type RejectionReason uint32

const (
	Prohibited RejectionReason = iota + 1
	ConnectionFailed
	UnknownChannelType
	ResourceShortage
)

type channel struct {
	conn              // the underlying transport
	localId, remoteId uint32
	remoteWin         window
	maxPacketSize     uint32

	theyClosed  bool // indicates the close msg has been received from the remote side
	weClosed    bool // incidates the close msg has been sent from our side
	theySentEOF bool // used by serverChan
	dead        bool // used by ServerChan to force close
}

func (c *channel) sendWindowAdj(n int) error {
	msg := windowAdjustMsg{
		PeersId:         c.remoteId,
		AdditionalBytes: uint32(n),
	}
	return c.writePacket(marshal(msgChannelWindowAdjust, msg))
}

// sendClose signals the intent to close the channel.
func (c *channel) sendClose() error {
	return c.writePacket(marshal(msgChannelClose, channelCloseMsg{
		PeersId: c.remoteId,
	}))
}

// sendEOF sends EOF to the server. RFC 4254 Section 5.3
func (c *channel) sendEOF() error {
	return c.writePacket(marshal(msgChannelEOF, channelEOFMsg{
		PeersId: c.remoteId,
	}))
}

func (c *channel) sendChannelOpenFailure(reason RejectionReason, message string) error {
	reject := channelOpenFailureMsg{
		PeersId:  c.remoteId,
		Reason:   reason,
		Message:  message,
		Language: "en",
	}
	return c.writePacket(marshal(msgChannelOpenFailure, reject))
}

type serverChan struct {
	channel
	// immutable once created
	chanType  string
	extraData []byte

	serverConn *ServerConn
	myWindow   uint32
	err        error

	pendingRequests []ChannelRequest
	pendingData     []byte
	head, length    int

	// This lock is inferior to serverConn.lock
	cond *sync.Cond
}

func (c *serverChan) Accept() error {
	c.serverConn.lock.Lock()
	defer c.serverConn.lock.Unlock()

	if c.serverConn.err != nil {
		return c.serverConn.err
	}

	confirm := channelOpenConfirmMsg{
		PeersId:       c.remoteId,
		MyId:          c.localId,
		MyWindow:      c.myWindow,
		MaxPacketSize: c.maxPacketSize,
	}
	return c.writePacket(marshal(msgChannelOpenConfirm, confirm))
}

func (c *serverChan) Reject(reason RejectionReason, message string) error {
	c.serverConn.lock.Lock()
	defer c.serverConn.lock.Unlock()

	if c.serverConn.err != nil {
		return c.serverConn.err
	}

	return c.sendChannelOpenFailure(reason, message)
}

func (c *serverChan) handlePacket(packet interface{}) {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()

	switch packet := packet.(type) {
	case *channelRequestMsg:
		req := ChannelRequest{
			Request:   packet.Request,
			WantReply: packet.WantReply,
			Payload:   packet.RequestSpecificData,
		}

		c.pendingRequests = append(c.pendingRequests, req)
		c.cond.Signal()
	case *channelCloseMsg:
		c.theyClosed = true
		c.cond.Signal()
	case *channelEOFMsg:
		c.theySentEOF = true
		c.cond.Signal()
	case *windowAdjustMsg:
		if !c.remoteWin.add(packet.AdditionalBytes) {
			panic("illegal window update")
		}
	default:
		panic("unknown packet type")
	}
}

func (c *serverChan) handleData(data []byte) {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()

	// The other side should never send us more than our window.
	if len(data)+c.length > len(c.pendingData) {
		// TODO(agl): we should tear down the channel with a protocol
		// error.
		return
	}

	c.myWindow -= uint32(len(data))
	for i := 0; i < 2; i++ {
		tail := c.head + c.length
		if tail >= len(c.pendingData) {
			tail -= len(c.pendingData)
		}
		n := copy(c.pendingData[tail:], data)
		data = data[n:]
		c.length += n
	}

	c.cond.Signal()
}

func (c *serverChan) Stderr() io.Writer {
	return extendedDataChannel{c: c, t: extendedDataStderr}
}

// extendedDataChannel is an io.Writer that writes any data to c as extended
// data of the given type.
type extendedDataChannel struct {
	t extendedDataTypeCode
	c *serverChan
}

func (edc extendedDataChannel) Write(data []byte) (n int, err error) {
	c := edc.c
	for len(data) > 0 {
		var space uint32
		if space, err = c.getWindowSpace(uint32(len(data))); err != nil {
			return 0, err
		}
		todo := data
		if uint32(len(todo)) > space {
			todo = todo[:space]
		}

		packet := make([]byte, 1+4+4+4+len(todo))
		packet[0] = msgChannelExtendedData
		marshalUint32(packet[1:], c.remoteId)
		marshalUint32(packet[5:], uint32(edc.t))
		marshalUint32(packet[9:], uint32(len(todo)))
		copy(packet[13:], todo)

		if err = c.writePacket(packet); err != nil {
			return
		}

		n += len(todo)
		data = data[len(todo):]
	}

	return
}

func (c *serverChan) Read(data []byte) (n int, err error) {
	n, err, windowAdjustment := c.read(data)

	if windowAdjustment > 0 {
		packet := marshal(msgChannelWindowAdjust, windowAdjustMsg{
			PeersId:         c.remoteId,
			AdditionalBytes: windowAdjustment,
		})
		err = c.writePacket(packet)
	}

	return
}

func (c *serverChan) read(data []byte) (n int, err error, windowAdjustment uint32) {
	c.cond.L.Lock()
	defer c.cond.L.Unlock()

	if c.err != nil {
		return 0, c.err, 0
	}

	for {
		if c.theySentEOF || c.theyClosed || c.dead {
			return 0, io.EOF, 0
		}

		if len(c.pendingRequests) > 0 {
			req := c.pendingRequests[0]
			if len(c.pendingRequests) == 1 {
				c.pendingRequests = nil
			} else {
				oldPendingRequests := c.pendingRequests
				c.pendingRequests = make([]ChannelRequest, len(oldPendingRequests)-1)
				copy(c.pendingRequests, oldPendingRequests[1:])
			}

			return 0, req, 0
		}

		if c.length > 0 {
			tail := min(c.head+c.length, len(c.pendingData))
			n = copy(data, c.pendingData[c.head:tail])
			c.head += n
			c.length -= n
			if c.head == len(c.pendingData) {
				c.head = 0
			}

			windowAdjustment = uint32(len(c.pendingData)-c.length) - c.myWindow
			if windowAdjustment < uint32(len(c.pendingData)/2) {
				windowAdjustment = 0
			}
			c.myWindow += windowAdjustment

			return
		}

		c.cond.Wait()
	}

	panic("unreachable")
}

// getWindowSpace takes, at most, max bytes of space from the peer's window. It
// returns the number of bytes actually reserved.
func (c *serverChan) getWindowSpace(max uint32) (uint32, error) {
	var err error
	// TODO(dfc) This lock and check of c.weClosed is necessary because unlike
	// clientChan, c.weClosed is observed by more than one goroutine.
	c.cond.L.Lock()
	if c.dead || c.weClosed {
		err = io.EOF
	}
	c.cond.L.Unlock()
	if err != nil {
		return 0, err
	}
	return c.remoteWin.reserve(max), nil
}

func (c *serverChan) Write(data []byte) (n int, err error) {
	for len(data) > 0 {
		var space uint32
		if space, err = c.getWindowSpace(uint32(len(data))); err != nil {
			return 0, err
		}
		todo := data
		if uint32(len(todo)) > space {
			todo = todo[:space]
		}

		packet := make([]byte, 1+4+4+len(todo))
		packet[0] = msgChannelData
		marshalUint32(packet[1:], c.remoteId)
		marshalUint32(packet[5:], uint32(len(todo)))
		copy(packet[9:], todo)

		if err = c.writePacket(packet); err != nil {
			return
		}

		n += len(todo)
		data = data[len(todo):]
	}

	return
}

func (c *serverChan) Close() error {
	c.serverConn.lock.Lock()
	defer c.serverConn.lock.Unlock()

	if c.serverConn.err != nil {
		return c.serverConn.err
	}

	if c.weClosed {
		return errors.New("ssh: channel already closed")
	}
	c.weClosed = true

	return c.sendClose()
}

func (c *serverChan) AckRequest(ok bool) error {
	c.serverConn.lock.Lock()
	defer c.serverConn.lock.Unlock()

	if c.serverConn.err != nil {
		return c.serverConn.err
	}

	if !ok {
		ack := channelRequestFailureMsg{
			PeersId: c.remoteId,
		}
		return c.writePacket(marshal(msgChannelFailure, ack))
	}

	ack := channelRequestSuccessMsg{
		PeersId: c.remoteId,
	}
	return c.writePacket(marshal(msgChannelSuccess, ack))
}

func (c *serverChan) ChannelType() string {
	return c.chanType
}

func (c *serverChan) ExtraData() []byte {
	return c.extraData
}

// A clientChan represents a single RFC 4254 channel multiplexed 
// over a SSH connection.
type clientChan struct {
	channel
	stdin  *chanWriter
	stdout *chanReader
	stderr *chanReader
	msg    chan interface{}
}

// newClientChan returns a partially constructed *clientChan
// using the local id provided. To be usable clientChan.remoteId
// needs to be assigned once known.
func newClientChan(cc conn, id uint32) *clientChan {
	c := &clientChan{
		channel: channel{
			conn:      cc,
			localId:   id,
			remoteWin: window{Cond: newCond()},
		},
		msg: make(chan interface{}, 16),
	}
	c.stdin = &chanWriter{
		channel: &c.channel,
	}
	c.stdout = &chanReader{
		channel: &c.channel,
		buffer:  newBuffer(),
	}
	c.stderr = &chanReader{
		channel: &c.channel,
		buffer:  newBuffer(),
	}
	return c
}

// waitForChannelOpenResponse, if successful, fills out
// the remoteId and records any initial window advertisement.
func (c *clientChan) waitForChannelOpenResponse() error {
	switch msg := (<-c.msg).(type) {
	case *channelOpenConfirmMsg:
		// fixup remoteId field
		c.remoteId = msg.MyId
		// TODO(dfc) asset this is < 2^31.
		c.maxPacketSize = msg.MaxPacketSize
		c.remoteWin.add(msg.MyWindow)
		return nil
	case *channelOpenFailureMsg:
		return errors.New(safeString(msg.Message))
	}
	return errors.New("ssh: unexpected packet")
}

// Close closes the channel. This does not close the underlying connection.
func (c *clientChan) Close() error {
	if !c.weClosed {
		c.weClosed = true
		return c.sendClose()
	}
	return nil
}

// A chanWriter represents the stdin of a remote process.
type chanWriter struct {
	*channel
}

// Write writes data to the remote process's standard input.
func (w *chanWriter) Write(data []byte) (written int, err error) {
	for len(data) > 0 {
		// never send more data than maxPacketSize even if
		// there is sufficent window.
		n := min(int(w.maxPacketSize), len(data))
		n = int(w.remoteWin.reserve(uint32(n)))
		remoteId := w.remoteId
		packet := []byte{
			msgChannelData,
			byte(remoteId >> 24), byte(remoteId >> 16), byte(remoteId >> 8), byte(remoteId),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
		if err = w.writePacket(append(packet, data[:n]...)); err != nil {
			break
		}
		data = data[n:]
		written += n
	}
	return
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (w *chanWriter) Close() error {
	return w.sendEOF()
}

// A chanReader represents stdout or stderr of a remote process.
type chanReader struct {
	*channel // the channel backing this reader
	*buffer
}

// Read reads data from the remote process's stdout or stderr.
func (r *chanReader) Read(buf []byte) (int, error) {
	n, err := r.buffer.Read(buf)
	if err != nil {
		if err == io.EOF {
			return n, err
		}
		return 0, err
	}
	return n, r.sendWindowAdj(n)
}
