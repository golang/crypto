// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"

	_ "crypto/sha1"
)

type ServerConfig struct {
	rsa *rsa.PrivateKey

	// rsaSerialized is the serialized form of the public key that
	// corresponds to the private key held in the rsa field.
	rsaSerialized []byte

	// Rand provides the source of entropy for key exchange. If Rand is
	// nil, the cryptographic random reader in package crypto/rand will
	// be used.
	Rand io.Reader

	// NoClientAuth is true if clients are allowed to connect without
	// authenticating.
	NoClientAuth bool

	// PasswordCallback, if non-nil, is called when a user attempts to
	// authenticate using a password. It may be called concurrently from
	// several goroutines.
	PasswordCallback func(conn *ServerConn, user, password string) bool

	// PublicKeyCallback, if non-nil, is called when a client attempts public
	// key authentication. It must return true iff the given public key is
	// valid for the given user.
	PublicKeyCallback func(conn *ServerConn, user, algo string, pubkey []byte) bool

	// KeyboardInteractiveCallback, if non-nil, is called when
	// keyboard-interactive authentication is selected (RFC
	// 4256). The client object's Challenge function should be
	// used to query the user. The callback may offer multiple
	// Challenge rounds. To avoid information leaks, the client
	// should be presented a challenge even if the user is
	// unknown.
	KeyboardInteractiveCallback func(conn *ServerConn, user string, client ClientKeyboardInteractive) bool

	// Cryptographic-related configuration.
	Crypto CryptoConfig
}

func (c *ServerConfig) rand() io.Reader {
	if c.Rand == nil {
		return rand.Reader
	}
	return c.Rand
}

// SetRSAPrivateKey sets the private key for a Server. A Server must have a
// private key configured in order to accept connections. The private key must
// be in the form of a PEM encoded, PKCS#1, RSA private key. The file "id_rsa"
// typically contains such a key.
func (s *ServerConfig) SetRSAPrivateKey(pemBytes []byte) error {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return errors.New("ssh: no key found")
	}
	rsa, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	s.rsa = rsa
	s.rsaSerialized = MarshalPublicKey(NewRSAPublicKey(&rsa.PublicKey))
	return nil
}

// cachedPubKey contains the results of querying whether a public key is
// acceptable for a user. The cache only applies to a single ServerConn.
type cachedPubKey struct {
	user, algo string
	pubKey     []byte
	result     bool
}

const maxCachedPubKeys = 16

// A ServerConn represents an incoming connection.
type ServerConn struct {
	*transport
	config *ServerConfig

	channels   map[uint32]*serverChan
	nextChanId uint32

	// lock protects err and channels.
	lock sync.Mutex
	err  error

	// cachedPubKeys contains the cache results of tests for public keys.
	// Since SSH clients will query whether a public key is acceptable
	// before attempting to authenticate with it, we end up with duplicate
	// queries for public key validity.
	cachedPubKeys []cachedPubKey

	// User holds the successfully authenticated user name.
	// It is empty if no authentication is used.  It is populated before
	// any authentication callback is called and not assigned to after that.
	User string

	// ClientVersion is the client's version, populated after
	// Handshake is called. It should not be modified.
	ClientVersion []byte

	// Initial H used for the session ID. Once assigned this must not change
	// even during subsequent key exchanges.
	sessionId []byte
}

// Server returns a new SSH server connection
// using c as the underlying transport.
func Server(c net.Conn, config *ServerConfig) *ServerConn {
	return &ServerConn{
		transport: newTransport(c, config.rand()),
		channels:  make(map[uint32]*serverChan),
		config:    config,
	}
}

// kexECDH performs Elliptic Curve Diffie-Hellman key agreement on a
// ServerConnection, as documented in RFC 5656, section 4.
func (s *ServerConn) kexECDH(curve elliptic.Curve, magics *handshakeMagics, hostKeyAlgo string) (result *kexResult, err error) {
	packet, err := s.readPacket()
	if err != nil {
		return
	}

	var kexECDHInit kexECDHInitMsg
	if err = unmarshal(&kexECDHInit, packet, msgKexECDHInit); err != nil {
		return
	}

	clientX, clientY := elliptic.Unmarshal(curve, kexECDHInit.ClientPubKey)
	if clientX == nil {
		return nil, errors.New("ssh: elliptic.Unmarshal failure")
	}

	if !validateECPublicKey(curve, clientX, clientY) {
		return nil, errors.New("ssh: not a valid EC public key")
	}

	// We could cache this key across multiple users/multiple
	// connection attempts, but the benefit is small. OpenSSH
	// generates a new key for each incoming connection.
	ephKey, err := ecdsa.GenerateKey(curve, s.config.rand())
	if err != nil {
		return nil, err
	}

	hostKeyBytes := s.config.rsaSerialized

	serializedEphKey := elliptic.Marshal(curve, ephKey.PublicKey.X, ephKey.PublicKey.Y)

	// generate shared secret
	secret, _ := curve.ScalarMult(clientX, clientY, ephKey.D.Bytes())

	hashFunc := ecHash(curve)
	h := hashFunc.New()
	writeString(h, magics.clientVersion)
	writeString(h, magics.serverVersion)
	writeString(h, magics.clientKexInit)
	writeString(h, magics.serverKexInit)
	writeString(h, hostKeyBytes)
	writeString(h, kexECDHInit.ClientPubKey)
	writeString(h, serializedEphKey)

	K := make([]byte, intLength(secret))
	marshalInt(K, secret)
	h.Write(K)

	H := h.Sum(nil)

	sig, err := s.serializedHostKeySignature(hostKeyAlgo, H)
	if err != nil {
		return nil, err
	}

	reply := kexECDHReplyMsg{
		EphemeralPubKey: serializedEphKey,
		HostKey:         hostKeyBytes,
		Signature:       sig,
	}

	serialized := marshal(msgKexECDHReply, reply)
	if err := s.writePacket(serialized); err != nil {
		return nil, err
	}

	return &kexResult{
		H:       H,
		K:       K,
		HostKey: reply.HostKey,
		Hash:    hashFunc,
	}, nil
}

// validateECPublicKey checks that the point is a valid public key for
// the given curve. See [SEC1], 3.2.2
func validateECPublicKey(curve elliptic.Curve, x, y *big.Int) bool {
	if x.Sign() == 0 && y.Sign() == 0 {
		return false
	}

	if x.Cmp(curve.Params().P) >= 0 {
		return false
	}

	if y.Cmp(curve.Params().P) >= 0 {
		return false
	}

	if !curve.IsOnCurve(x, y) {
		return false
	}

	// We don't check if N * PubKey == 0, since
	//
	// - the NIST curves have cofactor = 1, so this is implicit.
	// (We don't forsee an implementation that supports non NIST
	// curves)
	//
	// - for ephemeral keys, we don't need to worry about small
	// subgroup attacks.
	return true
}

// kexDH performs Diffie-Hellman key agreement on a ServerConnection.
func (s *ServerConn) kexDH(group *dhGroup, hashFunc crypto.Hash, magics *handshakeMagics, hostKeyAlgo string) (result *kexResult, err error) {
	packet, err := s.readPacket()
	if err != nil {
		return
	}
	var kexDHInit kexDHInitMsg
	if err = unmarshal(&kexDHInit, packet, msgKexDHInit); err != nil {
		return
	}

	y, err := rand.Int(s.config.rand(), group.p)
	if err != nil {
		return
	}

	Y := new(big.Int).Exp(group.g, y, group.p)
	kInt, err := group.diffieHellman(kexDHInit.X, y)
	if err != nil {
		return nil, err
	}

	hostKeyBytes := s.config.rsaSerialized

	h := hashFunc.New()
	writeString(h, magics.clientVersion)
	writeString(h, magics.serverVersion)
	writeString(h, magics.clientKexInit)
	writeString(h, magics.serverKexInit)
	writeString(h, hostKeyBytes)
	writeInt(h, kexDHInit.X)
	writeInt(h, Y)

	K := make([]byte, intLength(kInt))
	marshalInt(K, kInt)
	h.Write(K)

	H := h.Sum(nil)

	sig, err := s.serializedHostKeySignature(hostKeyAlgo, H)
	if err != nil {
		return nil, err
	}

	kexDHReply := kexDHReplyMsg{
		HostKey:   hostKeyBytes,
		Y:         Y,
		Signature: sig,
	}
	packet = marshal(msgKexDHReply, kexDHReply)

	err = s.writePacket(packet)
	return &kexResult{
		H:       H,
		K:       K,
		HostKey: hostKeyBytes,
		Hash:    hashFunc,
	}, nil
}

// serializedHostKeySignature signs the hashed data, and serializes
// the signature according to SSH conventions.
func (s *ServerConn) serializedHostKeySignature(hostKeyAlgo string, hashed []byte) ([]byte, error) {
	var sig []byte
	switch hostKeyAlgo {
	case hostAlgoRSA:
		hashFunc := crypto.SHA1
		hh := hashFunc.New()
		hh.Write(hashed)
		var err error
		sig, err = rsa.SignPKCS1v15(s.config.rand(), s.config.rsa, hashFunc, hh.Sum(nil))
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("ssh: internal error")
	}

	return serializeSignature(hostKeyAlgo, sig), nil
}

// serverVersion is the fixed identification string that Server will use.
var serverVersion = []byte("SSH-2.0-Go\r\n")

// Handshake performs an SSH transport and client authentication on the given ServerConn.
func (s *ServerConn) Handshake() (err error) {
	if _, err = s.Write(serverVersion); err != nil {
		return
	}
	if err = s.Flush(); err != nil {
		return
	}

	s.ClientVersion, err = readVersion(s)
	if err != nil {
		return
	}
	if err = s.clientInitHandshake(nil, nil); err != nil {
		return
	}

	var packet []byte
	if packet, err = s.readPacket(); err != nil {
		return
	}
	var serviceRequest serviceRequestMsg
	if err = unmarshal(&serviceRequest, packet, msgServiceRequest); err != nil {
		return
	}
	if serviceRequest.Service != serviceUserAuth {
		return errors.New("ssh: requested service '" + serviceRequest.Service + "' before authenticating")
	}
	serviceAccept := serviceAcceptMsg{
		Service: serviceUserAuth,
	}
	if err = s.writePacket(marshal(msgServiceAccept, serviceAccept)); err != nil {
		return
	}

	if err = s.authenticate(s.sessionId); err != nil {
		return
	}
	return
}

func (s *ServerConn) clientInitHandshake(clientKexInit *kexInitMsg, clientKexInitPacket []byte) (err error) {
	serverKexInit := kexInitMsg{
		KexAlgos:                s.config.Crypto.kexes(),
		ServerHostKeyAlgos:      supportedHostKeyAlgos,
		CiphersClientServer:     s.config.Crypto.ciphers(),
		CiphersServerClient:     s.config.Crypto.ciphers(),
		MACsClientServer:        s.config.Crypto.macs(),
		MACsServerClient:        s.config.Crypto.macs(),
		CompressionClientServer: supportedCompressions,
		CompressionServerClient: supportedCompressions,
	}
	serverKexInitPacket := marshal(msgKexInit, serverKexInit)

	if err = s.writePacket(serverKexInitPacket); err != nil {
		return
	}

	if clientKexInitPacket == nil {
		clientKexInit = new(kexInitMsg)
		if clientKexInitPacket, err = s.readPacket(); err != nil {
			return
		}
		if err = unmarshal(clientKexInit, clientKexInitPacket, msgKexInit); err != nil {
			return
		}
	}

	kexAlgo, hostKeyAlgo, ok := findAgreedAlgorithms(s.transport, clientKexInit, &serverKexInit)
	if !ok {
		return errors.New("ssh: no common algorithms")
	}
	if clientKexInit.FirstKexFollows && kexAlgo != clientKexInit.KexAlgos[0] {
		// The client sent a Kex message for the wrong algorithm,
		// which we have to ignore.
		if _, err = s.readPacket(); err != nil {
			return
		}
	}

	var magics handshakeMagics
	magics.serverVersion = serverVersion[:len(serverVersion)-2]
	magics.clientVersion = s.ClientVersion
	magics.serverKexInit = marshal(msgKexInit, serverKexInit)
	magics.clientKexInit = clientKexInitPacket

	var result *kexResult
	switch kexAlgo {
	case kexAlgoECDH256:
		result, err = s.kexECDH(elliptic.P256(), &magics, hostKeyAlgo)
	case kexAlgoECDH384:
		result, err = s.kexECDH(elliptic.P384(), &magics, hostKeyAlgo)
	case kexAlgoECDH521:
		result, err = s.kexECDH(elliptic.P521(), &magics, hostKeyAlgo)
	case kexAlgoDH14SHA1:
		dhGroup14Once.Do(initDHGroup14)
		result, err = s.kexDH(dhGroup14, crypto.SHA1, &magics, hostKeyAlgo)
	case kexAlgoDH1SHA1:
		dhGroup1Once.Do(initDHGroup1)
		result, err = s.kexDH(dhGroup1, crypto.SHA1, &magics, hostKeyAlgo)
	default:
		err = errors.New("ssh: unexpected key exchange algorithm " + kexAlgo)
	}
	if err != nil {
		return
	}
	// sessionId must only be assigned during initial handshake.
	if s.sessionId == nil {
		s.sessionId = result.H
	}

	var packet []byte

	if err = s.writePacket([]byte{msgNewKeys}); err != nil {
		return
	}
	if err = s.transport.writer.setupKeys(serverKeys, result.K, result.H, s.sessionId, result.Hash); err != nil {
		return
	}

	if packet, err = s.readPacket(); err != nil {
		return
	}
	if packet[0] != msgNewKeys {
		return UnexpectedMessageError{msgNewKeys, packet[0]}
	}
	if err = s.transport.reader.setupKeys(clientKeys, result.K, result.H, s.sessionId, result.Hash); err != nil {
		return
	}

	return
}

func isAcceptableAlgo(algo string) bool {
	switch algo {
	case KeyAlgoRSA, KeyAlgoDSA, KeyAlgoECDSA256, KeyAlgoECDSA384, KeyAlgoECDSA521,
		CertAlgoRSAv01, CertAlgoDSAv01, CertAlgoECDSA256v01, CertAlgoECDSA384v01, CertAlgoECDSA521v01:
		return true
	}
	return false
}

// testPubKey returns true if the given public key is acceptable for the user.
func (s *ServerConn) testPubKey(user, algo string, pubKey []byte) bool {
	if s.config.PublicKeyCallback == nil || !isAcceptableAlgo(algo) {
		return false
	}

	for _, c := range s.cachedPubKeys {
		if c.user == user && c.algo == algo && bytes.Equal(c.pubKey, pubKey) {
			return c.result
		}
	}

	result := s.config.PublicKeyCallback(s, user, algo, pubKey)
	if len(s.cachedPubKeys) < maxCachedPubKeys {
		c := cachedPubKey{
			user:   user,
			algo:   algo,
			pubKey: make([]byte, len(pubKey)),
			result: result,
		}
		copy(c.pubKey, pubKey)
		s.cachedPubKeys = append(s.cachedPubKeys, c)
	}

	return result
}

func (s *ServerConn) authenticate(H []byte) error {
	var userAuthReq userAuthRequestMsg
	var err error
	var packet []byte

userAuthLoop:
	for {
		if packet, err = s.readPacket(); err != nil {
			return err
		}
		if err = unmarshal(&userAuthReq, packet, msgUserAuthRequest); err != nil {
			return err
		}

		if userAuthReq.Service != serviceSSH {
			return errors.New("ssh: client attempted to negotiate for unknown service: " + userAuthReq.Service)
		}

		switch userAuthReq.Method {
		case "none":
			if s.config.NoClientAuth {
				break userAuthLoop
			}
		case "password":
			if s.config.PasswordCallback == nil {
				break
			}
			payload := userAuthReq.Payload
			if len(payload) < 1 || payload[0] != 0 {
				return ParseError{msgUserAuthRequest}
			}
			payload = payload[1:]
			password, payload, ok := parseString(payload)
			if !ok || len(payload) > 0 {
				return ParseError{msgUserAuthRequest}
			}

			s.User = userAuthReq.User
			if s.config.PasswordCallback(s, userAuthReq.User, string(password)) {
				break userAuthLoop
			}
		case "keyboard-interactive":
			if s.config.KeyboardInteractiveCallback == nil {
				break
			}

			s.User = userAuthReq.User
			if s.config.KeyboardInteractiveCallback(s, s.User, &sshClientKeyboardInteractive{s}) {
				break userAuthLoop
			}
		case "publickey":
			if s.config.PublicKeyCallback == nil {
				break
			}
			payload := userAuthReq.Payload
			if len(payload) < 1 {
				return ParseError{msgUserAuthRequest}
			}
			isQuery := payload[0] == 0
			payload = payload[1:]
			algoBytes, payload, ok := parseString(payload)
			if !ok {
				return ParseError{msgUserAuthRequest}
			}
			algo := string(algoBytes)

			pubKey, payload, ok := parseString(payload)
			if !ok {
				return ParseError{msgUserAuthRequest}
			}
			if isQuery {
				// The client can query if the given public key
				// would be ok.
				if len(payload) > 0 {
					return ParseError{msgUserAuthRequest}
				}
				if s.testPubKey(userAuthReq.User, algo, pubKey) {
					okMsg := userAuthPubKeyOkMsg{
						Algo:   algo,
						PubKey: string(pubKey),
					}
					if err = s.writePacket(marshal(msgUserAuthPubKeyOk, okMsg)); err != nil {
						return err
					}
					continue userAuthLoop
				}
			} else {
				sig, payload, ok := parseSignature(payload)
				if !ok || len(payload) > 0 {
					return ParseError{msgUserAuthRequest}
				}
				// Ensure the public key algo and signature algo
				// are supported.  Compare the private key
				// algorithm name that corresponds to algo with
				// sig.Format.  This is usually the same, but
				// for certs, the names differ.
				if !isAcceptableAlgo(algo) || !isAcceptableAlgo(sig.Format) || pubAlgoToPrivAlgo(algo) != sig.Format {
					break
				}
				signedData := buildDataSignedForAuth(H, userAuthReq, algoBytes, pubKey)
				key, _, ok := parsePubKey(pubKey)
				if !ok {
					return ParseError{msgUserAuthRequest}
				}

				if !key.Verify(signedData, sig.Blob) {
					return ParseError{msgUserAuthRequest}
				}
				// TODO(jmpittman): Implement full validation for certificates.
				s.User = userAuthReq.User
				if s.testPubKey(userAuthReq.User, algo, pubKey) {
					break userAuthLoop
				}
			}
		}

		var failureMsg userAuthFailureMsg
		if s.config.PasswordCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "password")
		}
		if s.config.PublicKeyCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "publickey")
		}
		if s.config.KeyboardInteractiveCallback != nil {
			failureMsg.Methods = append(failureMsg.Methods, "keyboard-interactive")
		}

		if len(failureMsg.Methods) == 0 {
			return errors.New("ssh: no authentication methods configured but NoClientAuth is also false")
		}

		if err = s.writePacket(marshal(msgUserAuthFailure, failureMsg)); err != nil {
			return err
		}
	}

	packet = []byte{msgUserAuthSuccess}
	if err = s.writePacket(packet); err != nil {
		return err
	}

	return nil
}

// sshClientKeyboardInteractive implements a ClientKeyboardInteractive by
// asking the client on the other side of a ServerConn.
type sshClientKeyboardInteractive struct {
	*ServerConn
}

func (c *sshClientKeyboardInteractive) Challenge(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
	if len(questions) != len(echos) {
		return nil, errors.New("ssh: echos and questions must have equal length")
	}

	var prompts []byte
	for i := range questions {
		prompts = appendString(prompts, questions[i])
		prompts = appendBool(prompts, echos[i])
	}

	if err := c.writePacket(marshal(msgUserAuthInfoRequest, userAuthInfoRequestMsg{
		Instruction: instruction,
		NumPrompts:  uint32(len(questions)),
		Prompts:     prompts,
	})); err != nil {
		return nil, err
	}

	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	if packet[0] != msgUserAuthInfoResponse {
		return nil, UnexpectedMessageError{msgUserAuthInfoResponse, packet[0]}
	}
	packet = packet[1:]

	n, packet, ok := parseUint32(packet)
	if !ok || int(n) != len(questions) {
		return nil, &ParseError{msgUserAuthInfoResponse}
	}

	for i := uint32(0); i < n; i++ {
		ans, rest, ok := parseString(packet)
		if !ok {
			return nil, &ParseError{msgUserAuthInfoResponse}
		}

		answers = append(answers, string(ans))
		packet = rest
	}
	if len(packet) != 0 {
		return nil, errors.New("ssh: junk at end of message")
	}

	return answers, nil
}

const defaultWindowSize = 32768

// Accept reads and processes messages on a ServerConn. It must be called
// in order to demultiplex messages to any resulting Channels.
func (s *ServerConn) Accept() (Channel, error) {
	// TODO(dfc) s.lock is not held here so visibility of s.err is not guaranteed.
	if s.err != nil {
		return nil, s.err
	}

	for {
		packet, err := s.readPacket()
		if err != nil {

			s.lock.Lock()
			s.err = err
			s.lock.Unlock()

			// TODO(dfc) s.lock protects s.channels but isn't being held here.
			for _, c := range s.channels {
				c.setDead()
				c.handleData(nil)
			}

			return nil, err
		}

		switch packet[0] {
		case msgChannelData:
			if len(packet) < 9 {
				// malformed data packet
				return nil, ParseError{msgChannelData}
			}
			remoteId := binary.BigEndian.Uint32(packet[1:5])
			s.lock.Lock()
			c, ok := s.channels[remoteId]
			if !ok {
				s.lock.Unlock()
				continue
			}
			if length := binary.BigEndian.Uint32(packet[5:9]); length > 0 {
				packet = packet[9:]
				c.handleData(packet[:length])
			}
			s.lock.Unlock()
		default:
			decoded, err := decode(packet)
			if err != nil {
				return nil, err
			}
			switch msg := decoded.(type) {
			case *channelOpenMsg:
				if msg.MaxPacketSize < minPacketLength || msg.MaxPacketSize > 1<<31 {
					return nil, errors.New("ssh: invalid MaxPacketSize from peer")
				}
				c := &serverChan{
					channel: channel{
						conn:      s,
						remoteId:  msg.PeersId,
						remoteWin: window{Cond: newCond()},
						maxPacket: msg.MaxPacketSize,
					},
					chanType:    msg.ChanType,
					extraData:   msg.TypeSpecificData,
					myWindow:    defaultWindowSize,
					serverConn:  s,
					cond:        newCond(),
					pendingData: make([]byte, defaultWindowSize),
				}
				c.remoteWin.add(msg.PeersWindow)
				s.lock.Lock()
				c.localId = s.nextChanId
				s.nextChanId++
				s.channels[c.localId] = c
				s.lock.Unlock()
				return c, nil

			case *channelRequestMsg:
				s.lock.Lock()
				c, ok := s.channels[msg.PeersId]
				if !ok {
					s.lock.Unlock()
					continue
				}
				c.handlePacket(msg)
				s.lock.Unlock()

			case *windowAdjustMsg:
				s.lock.Lock()
				c, ok := s.channels[msg.PeersId]
				if !ok {
					s.lock.Unlock()
					continue
				}
				c.handlePacket(msg)
				s.lock.Unlock()

			case *channelEOFMsg:
				s.lock.Lock()
				c, ok := s.channels[msg.PeersId]
				if !ok {
					s.lock.Unlock()
					continue
				}
				c.handlePacket(msg)
				s.lock.Unlock()

			case *channelCloseMsg:
				s.lock.Lock()
				c, ok := s.channels[msg.PeersId]
				if !ok {
					s.lock.Unlock()
					continue
				}
				c.handlePacket(msg)
				s.lock.Unlock()

			case *globalRequestMsg:
				if msg.WantReply {
					if err := s.writePacket([]byte{msgRequestFailure}); err != nil {
						return nil, err
					}
				}

			case *kexInitMsg:
				s.lock.Lock()
				if err := s.clientInitHandshake(msg, packet); err != nil {
					s.lock.Unlock()
					return nil, err
				}
				s.lock.Unlock()
			case *disconnectMsg:
				return nil, io.EOF
			default:
				// Unknown message. Ignore.
			}
		}
	}

	panic("unreachable")
}

// A Listener implements a network listener (net.Listener) for SSH connections.
type Listener struct {
	listener net.Listener
	config   *ServerConfig
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.listener.Addr()
}

// Close closes the listener.
func (l *Listener) Close() error {
	return l.listener.Close()
}

// Accept waits for and returns the next incoming SSH connection.
// The receiver should call Handshake() in another goroutine
// to avoid blocking the accepter.
func (l *Listener) Accept() (*ServerConn, error) {
	c, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	return Server(c, l.config), nil
}

// Listen creates an SSH listener accepting connections on
// the given network address using net.Listen.
func Listen(network, addr string, config *ServerConfig) (*Listener, error) {
	l, err := net.Listen(network, addr)
	if err != nil {
		return nil, err
	}
	return &Listener{
		l,
		config,
	}, nil
}
