// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
)

// clientVersion is the fixed identification string that the client will use.
var clientVersion = []byte("SSH-2.0-Go\r\n")

// ClientConn represents the client side of an SSH connection.
type ClientConn struct {
	*transport
	config      *ClientConfig
	chanlist    // channels associated with this connection
	forwardList // forwarded tcpip connections from the remote side
	globalRequest
}

type globalRequest struct {
	sync.Mutex
	response chan interface{}
}

// Client returns a new SSH client connection using c as the underlying transport.
func Client(c net.Conn, config *ClientConfig) (*ClientConn, error) {
	conn := &ClientConn{
		transport:     newTransport(c, config.rand()),
		config:        config,
		globalRequest: globalRequest{response: make(chan interface{}, 1)},
	}
	if err := conn.handshake(); err != nil {
		conn.Close()
		return nil, err
	}
	go conn.mainLoop()
	return conn, nil
}

// handshake performs the client side key exchange. See RFC 4253 Section 7.
func (c *ClientConn) handshake() error {
	var magics handshakeMagics

	if _, err := c.Write(clientVersion); err != nil {
		return err
	}
	if err := c.Flush(); err != nil {
		return err
	}
	magics.clientVersion = clientVersion[:len(clientVersion)-2]

	// read remote server version
	version, err := readVersion(c)
	if err != nil {
		return err
	}
	magics.serverVersion = version
	clientKexInit := kexInitMsg{
		KexAlgos:                supportedKexAlgos,
		ServerHostKeyAlgos:      supportedHostKeyAlgos,
		CiphersClientServer:     c.config.Crypto.ciphers(),
		CiphersServerClient:     c.config.Crypto.ciphers(),
		MACsClientServer:        c.config.Crypto.macs(),
		MACsServerClient:        c.config.Crypto.macs(),
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	kexInitPacket := marshal(msgKexInit, clientKexInit)
	magics.clientKexInit = kexInitPacket

	if err := c.writePacket(kexInitPacket); err != nil {
		return err
	}
	packet, err := c.readPacket()
	if err != nil {
		return err
	}

	magics.serverKexInit = packet

	var serverKexInit kexInitMsg
	if err = unmarshal(&serverKexInit, packet, msgKexInit); err != nil {
		return err
	}

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(c.transport, &clientKexInit, &serverKexInit)
	if !ok {
		return errors.New("ssh: no common algorithms")
	}

	if serverKexInit.FirstKexFollows && kexAlgo != serverKexInit.KexAlgos[0] {
		// The server sent a Kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err := c.readPacket(); err != nil {
			return err
		}
	}

	var H, K []byte
	var hashFunc crypto.Hash
	switch kexAlgo {
	case kexAlgoDH14SHA1:
		hashFunc = crypto.SHA1
		dhGroup14Once.Do(initDHGroup14)
		H, K, err = c.kexDH(dhGroup14, hashFunc, &magics, hostKeyAlgo)
	case keyAlgoDH1SHA1:
		hashFunc = crypto.SHA1
		dhGroup1Once.Do(initDHGroup1)
		H, K, err = c.kexDH(dhGroup1, hashFunc, &magics, hostKeyAlgo)
	default:
		err = fmt.Errorf("ssh: unexpected key exchange algorithm %v", kexAlgo)
	}
	if err != nil {
		return err
	}

	if err = c.writePacket([]byte{msgNewKeys}); err != nil {
		return err
	}
	if err = c.transport.writer.setupKeys(clientKeys, K, H, H, hashFunc); err != nil {
		return err
	}
	if packet, err = c.readPacket(); err != nil {
		return err
	}
	if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}
	if err := c.transport.reader.setupKeys(serverKeys, K, H, H, hashFunc); err != nil {
		return err
	}
	return c.authenticate(H)
}

// kexDH performs Diffie-Hellman key agreement on a ClientConn. The
// returned values are given the same names as in RFC 4253, section 8.
func (c *ClientConn) kexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) ([]byte, []byte, error) {
	x, err := rand.Int(c.config.rand(), group.p)
	if err != nil {
		return nil, nil, err
	}
	X := new(big.Int).Exp(group.g, x, group.p)
	kexDHInit := kexDHInitMsg{
		X: X,
	}
	if err := c.writePacket(marshal(msgKexDHInit, kexDHInit)); err != nil {
		return nil, nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, nil, err
	}

	var kexDHReply kexDHReplyMsg
	if err = unmarshal(&kexDHReply, packet, msgKexDHReply); err != nil {
		return nil, nil, err
	}

	kInt, err := group.diffieHellman(kexDHReply.Y, x)
	if err != nil {
		return nil, nil, err
	}

	h := hashFunc.New()
	writeString(h, magics.clientVersion)
	writeString(h, magics.serverVersion)
	writeString(h, magics.clientKexInit)
	writeString(h, magics.serverKexInit)
	writeString(h, kexDHReply.HostKey)
	writeInt(h, X)
	writeInt(h, kexDHReply.Y)
	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H := h.Sum(nil)

	return H, K, nil
}

// mainLoop reads incoming messages and routes channel messages
// to their respective ClientChans.
func (c *ClientConn) mainLoop() {
	defer func() {
		// We don't check, for example, that the channel IDs from the
		// server are valid before using them. Thus a bad server can
		// cause us to panic, but we don't want to crash the program.
		recover()

		c.Close()
		c.closeAll()
	}()

	for {
		packet, err := c.readPacket()
		if err != nil {
			break
		}
		// TODO(dfc) A note on blocking channel use.
		// The msg, data and dataExt channels of a clientChan can
		// cause this loop to block indefinately if the consumer does
		// not service them.
		switch packet[0] {
		case msgChannelData:
			if len(packet) < 9 {
				// malformed data packet
				return
			}
			peersId := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
			length := uint32(packet[5])<<24 | uint32(packet[6])<<16 | uint32(packet[7])<<8 | uint32(packet[8])
			packet = packet[9:]

			if length != uint32(len(packet)) {
				return
			}
			c.getChan(peersId).stdout.handleData(packet)
		case msgChannelExtendedData:
			if len(packet) < 13 {
				// malformed data packet
				return
			}
			peersId := uint32(packet[1])<<24 | uint32(packet[2])<<16 | uint32(packet[3])<<8 | uint32(packet[4])
			datatype := uint32(packet[5])<<24 | uint32(packet[6])<<16 | uint32(packet[7])<<8 | uint32(packet[8])
			length := uint32(packet[9])<<24 | uint32(packet[10])<<16 | uint32(packet[11])<<8 | uint32(packet[12])
			packet = packet[13:]

			if length != uint32(len(packet)) {
				return
			}
			// RFC 4254 5.2 defines data_type_code 1 to be data destined
			// for stderr on interactive sessions. Other data types are
			// silently discarded.
			if datatype == 1 {
				c.getChan(peersId).stderr.handleData(packet)
			}
		default:
			switch msg := decode(packet).(type) {
			case *channelOpenMsg:
				c.handleChanOpen(msg)
			case *channelOpenConfirmMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelOpenFailureMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelCloseMsg:
				ch := c.getChan(msg.PeersId)
				ch.theyClosed = true
				ch.stdout.eof()
				ch.stderr.eof()
				close(ch.msg)
				if !ch.weClosed {
					ch.weClosed = true
					ch.sendClose()
				}
				c.chanlist.remove(msg.PeersId)
			case *channelEOFMsg:
				ch := c.getChan(msg.PeersId)
				ch.stdout.eof()
				// RFC 4254 is mute on how EOF affects dataExt messages but
				// it is logical to signal EOF at the same time.
				ch.stderr.eof()
			case *channelRequestSuccessMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelRequestFailureMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *channelRequestMsg:
				c.getChan(msg.PeersId).msg <- msg
			case *windowAdjustMsg:
				if !c.getChan(msg.PeersId).stdin.win.add(msg.AdditionalBytes) {
					// invalid window update
					return
				}
			case *globalRequestSuccessMsg, *globalRequestFailureMsg:
				c.globalRequest.response <- msg
			case *disconnectMsg:
				return
			default:
				fmt.Printf("mainLoop: unhandled message %T: %v\n", msg, msg)
			}
		}
	}
}

// Handle channel open messages from the remote side.
func (c *ClientConn) handleChanOpen(msg *channelOpenMsg) {
	switch msg.ChanType {
	case "forwarded-tcpip":
		laddr, rest, ok := parseTCPAddr(msg.TypeSpecificData)
		if !ok {
			// invalid request
			c.sendConnectionFailed(msg.PeersId)
			return
		}
		l, ok := c.forwardList.lookup(laddr)
		if !ok {
			fmt.Println("could not find forward list entry for", laddr)
			// Section 7.2, implementations MUST reject suprious incoming
			// connections.
			c.sendConnectionFailed(msg.PeersId)
			return
		}
		raddr, rest, ok := parseTCPAddr(rest)
		if !ok {
			// invalid request
			c.sendConnectionFailed(msg.PeersId)
			return
		}
		ch := c.newChan(c.transport)
		ch.peersId = msg.PeersId
		ch.stdin.win.add(msg.PeersWindow)

		m := channelOpenConfirmMsg{
			PeersId:       ch.peersId,
			MyId:          ch.id,
			MyWindow:      1 << 14,
			MaxPacketSize: 1 << 15, // RFC 4253 6.1
		}
		c.writePacket(marshal(msgChannelOpenConfirm, m))
		l <- forward{ch, raddr}
	default:
		// unknown channel type
		m := channelOpenFailureMsg{
			PeersId:  msg.PeersId,
			Reason:   UnknownChannelType,
			Message:  fmt.Sprintf("unknown channel type: %v", msg.ChanType),
			Language: "en_US.UTF-8",
		}
		c.writePacket(marshal(msgChannelOpenFailure, m))
	}
}

// sendGlobalRequest sends a global request message as specified
// in RFC4254 section 4. To correctly synchronise messages, a lock
// is held internally until a response is returned.
func (c *ClientConn) sendGlobalRequest(m interface{}) (*globalRequestSuccessMsg, error) {
	c.globalRequest.Lock()
	defer c.globalRequest.Unlock()
	if err := c.writePacket(marshal(msgGlobalRequest, m)); err != nil {
		return nil, err
	}
	r := <-c.globalRequest.response
	if r, ok := r.(*globalRequestSuccessMsg); ok {
		return r, nil
	}
	return nil, errors.New("request failed")
}

// sendConnectionFailed rejects an incoming channel identified 
// by peersId.
func (c *ClientConn) sendConnectionFailed(peersId uint32) error {
	m := channelOpenFailureMsg{
		PeersId:  peersId,
		Reason:   ConnectionFailed,
		Message:  "invalid request",
		Language: "en_US.UTF-8",
	}
	return c.writePacket(marshal(msgChannelOpenFailure, m))
}

// parseTCPAddr parses the originating address from the remote into a *net.TCPAddr. 
// RFC 4254 section 7.2 is mute on what to do if parsing fails but the forwardlist
// requires a valid *net.TCPAddr to operate, so we enforce that restriction here.
func parseTCPAddr(b []byte) (*net.TCPAddr, []byte, bool) {
	addr, b, ok := parseString(b)
	if !ok {
		return nil, b, false
	}
	port, b, ok := parseUint32(b)
	if !ok {
		return nil, b, false
	}
	ip := net.ParseIP(string(addr))
	if ip == nil {
		return nil, b, false
	}
	return &net.TCPAddr{ip, int(port)}, b, true
}

// Dial connects to the given network address using net.Dial and
// then initiates a SSH handshake, returning the resulting client connection.
func Dial(network, addr string, config *ClientConfig) (*ClientConn, error) {
	conn, err := net.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return Client(conn, config)
}

// A ClientConfig structure is used to configure a ClientConn. After one has
// been passed to an SSH function it must not be modified.
type ClientConfig struct {
	// Rand provides the source of entropy for key exchange. If Rand is
	// nil, the cryptographic random reader in package crypto/rand will
	// be used.
	Rand io.Reader

	// The username to authenticate.
	User string

	// A slice of ClientAuth methods. Only the first instance
	// of a particular RFC 4252 method will be used during authentication.
	Auth []ClientAuth

	// Cryptographic-related configuration.
	Crypto CryptoConfig
}

func (c *ClientConfig) rand() io.Reader {
	if c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}

// A clientChan represents a single RFC 4254 channel that is multiplexed
// over a single SSH connection.
type clientChan struct {
	packetWriter
	id, peersId uint32
	stdin       *chanWriter      // receives window adjustments
	stdout      *chanReader      // receives the payload of channelData messages
	stderr      *chanReader      // receives the payload of channelExtendedData messages
	msg         chan interface{} // incoming messages
	theyClosed  bool             // indicates the close msg has been received from the remote side
	weClosed    bool             // incidates the close msg has been sent from our side
}

// newClientChan returns a partially constructed *clientChan
// using the local id provided. To be usable clientChan.peersId
// needs to be assigned once known.
func newClientChan(t *transport, id uint32) *clientChan {
	c := &clientChan{
		packetWriter: t,
		id:           id,
		msg:          make(chan interface{}, 16),
	}
	c.stdin = &chanWriter{
		win:        &window{Cond: sync.NewCond(new(sync.Mutex))},
		clientChan: c,
	}
	c.stdout = &chanReader{
		data:       make(chan []byte, 16),
		clientChan: c,
	}
	c.stderr = &chanReader{
		data:       make(chan []byte, 16),
		clientChan: c,
	}
	return c
}

// waitForChannelOpenResponse, if successful, fills out
// the peerId and records any initial window advertisement.
func (c *clientChan) waitForChannelOpenResponse() error {
	switch msg := (<-c.msg).(type) {
	case *channelOpenConfirmMsg:
		// fixup peersId field
		c.peersId = msg.MyId
		c.stdin.win.add(msg.MyWindow)
		return nil
	case *channelOpenFailureMsg:
		return errors.New(safeString(msg.Message))
	}
	return errors.New("ssh: unexpected packet")
}

// sendEOF sends EOF to the server. RFC 4254 Section 5.3
func (c *clientChan) sendEOF() error {
	return c.writePacket(marshal(msgChannelEOF, channelEOFMsg{
		PeersId: c.peersId,
	}))
}

// sendClose signals the intent to close the channel.
func (c *clientChan) sendClose() error {
	return c.writePacket(marshal(msgChannelClose, channelCloseMsg{
		PeersId: c.peersId,
	}))
}

func (c *clientChan) sendWindowAdj(n int) error {
	msg := windowAdjustMsg{
		PeersId:         c.peersId,
		AdditionalBytes: uint32(n),
	}
	return c.writePacket(marshal(msgChannelWindowAdjust, msg))
}

// Close closes the channel. This does not close the underlying connection.
func (c *clientChan) Close() error {
	if !c.weClosed {
		c.weClosed = true
		return c.sendClose()
	}
	return nil
}

// Thread safe channel list.
type chanlist struct {
	// protects concurrent access to chans
	sync.Mutex
	// chans are indexed by the local id of the channel, clientChan.id.
	// The PeersId value of messages received by ClientConn.mainLoop is
	// used to locate the right local clientChan in this slice.
	chans []*clientChan
}

// Allocate a new ClientChan with the next avail local id.
func (c *chanlist) newChan(t *transport) *clientChan {
	c.Lock()
	defer c.Unlock()
	for i := range c.chans {
		if c.chans[i] == nil {
			ch := newClientChan(t, uint32(i))
			c.chans[i] = ch
			return ch
		}
	}
	i := len(c.chans)
	ch := newClientChan(t, uint32(i))
	c.chans = append(c.chans, ch)
	return ch
}

func (c *chanlist) getChan(id uint32) *clientChan {
	c.Lock()
	defer c.Unlock()
	if id >= uint32(len(c.chans)) {
		return nil
	}
	return c.chans[int(id)]
}

func (c *chanlist) remove(id uint32) {
	c.Lock()
	defer c.Unlock()
	c.chans[int(id)] = nil
}

func (c *chanlist) closeAll() {
	c.Lock()
	defer c.Unlock()

	for _, ch := range c.chans {
		if ch == nil {
			continue
		}

		ch.theyClosed = true
		ch.stdout.eof()
		ch.stderr.eof()
		close(ch.msg)
	}
}

// A chanWriter represents the stdin of a remote process.
type chanWriter struct {
	win        *window
	clientChan *clientChan // the channel backing this writer
}

// Write writes data to the remote process's standard input.
func (w *chanWriter) Write(data []byte) (written int, err error) {
	for len(data) > 0 {
		// n cannot be larger than 2^31 as len(data) cannot
		// be larger than 2^31
		n := int(w.win.reserve(uint32(len(data))))
		peersId := w.clientChan.peersId
		packet := []byte{
			msgChannelData,
			byte(peersId >> 24), byte(peersId >> 16), byte(peersId >> 8), byte(peersId),
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n),
		}
		if err = w.clientChan.writePacket(append(packet, data[:n]...)); err != nil {
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
	return w.clientChan.sendEOF()
}

// A chanReader represents stdout or stderr of a remote process.
type chanReader struct {
	// TODO(dfc) a fixed size channel may not be the right data structure.
	// If writes to this channel block, they will block mainLoop, making
	// it unable to receive new messages from the remote side.
	data       chan []byte // receives data from remote
	dataClosed bool        // protects data from being closed twice
	clientChan *clientChan // the channel backing this reader
	buf        []byte
}

// eof signals to the consumer that there is no more data to be received.
func (r *chanReader) eof() {
	if !r.dataClosed {
		r.dataClosed = true
		close(r.data)
	}
}

// handleData sends buf to the reader's consumer. If r.data is closed
// the data will be silently discarded
func (r *chanReader) handleData(buf []byte) {
	if !r.dataClosed {
		r.data <- buf
	}
}

// Read reads data from the remote process's stdout or stderr.
func (r *chanReader) Read(data []byte) (int, error) {
	var ok bool
	for {
		if len(r.buf) > 0 {
			n := copy(data, r.buf)
			r.buf = r.buf[n:]
			return n, r.clientChan.sendWindowAdj(n)
		}
		r.buf, ok = <-r.data
		if !ok {
			return 0, io.EOF
		}
	}
	panic("unreachable")
}

// window represents the buffer available to clients 
// wishing to write to a channel.
type window struct {
	*sync.Cond
	win uint32 // RFC 4254 5.2 says the window size can grow to 2^32-1
}

// add adds win to the amount of window available
// for consumers.
func (w *window) add(win uint32) bool {
	if win == 0 {
		return false
	}
	w.L.Lock()
	if w.win+win < win {
		w.L.Unlock()
		return false
	}
	w.win += win
	// It is unusual that multiple goroutines would be attempting to reserve
	// window space, but not guaranteed. Use broadcast to notify all waiters 
	// that additional window is available.
	w.Broadcast()
	w.L.Unlock()
	return true
}

// reserve reserves win from the available window capacity.
// If no capacity remains, reserve will block. reserve may
// return less than requested.
func (w *window) reserve(win uint32) uint32 {
	w.L.Lock()
	for w.win == 0 {
		w.Wait()
	}
	if w.win < win {
		win = w.win
	}
	w.win -= win
	w.L.Unlock()
	return win
}
