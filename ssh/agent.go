// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// References
//   PROTOCOL.agent: http://www.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// See PROTOCOL.agent, section 3.
const (
	// 3.2 Requests from client to agent for protocol 2 key operations
	agentRequestIdentities   = 11
	agentSignRequest         = 13
	agentAddIdentity         = 17
	agentRemoveIdentity      = 18
	agentRemoveAllIdentities = 19
	agentAddIdConstrained    = 25

	// 3.3 Key-type independent requests from client to agent
	agentAddSmartcardKey            = 20
	agentRemoveSmartcardKey         = 21
	agentLock                       = 22
	agentUnlock                     = 23
	agentAddSmartcardKeyConstrained = 26

	// 3.4 Generic replies from agent to client
	agentFailure = 5
	agentSuccess = 6

	// 3.6 Replies from agent to client for protocol 2 key operations
	agentIdentitiesAnswer = 12
	agentSignResponse     = 14

	// 3.7 Key constraint identifiers
	agentConstrainLifetime = 1
	agentConstrainConfirm  = 2
)

// Agent messages:
// These structures mirror the wire format of the corresponding ssh agent
// messages found in PROTOCOL.agent.

type failureAgentMsg struct{}

type successAgentMsg struct{}

// See PROTOCOL.agent, section 2.5.2.
type requestIdentitiesAgentMsg struct{}

// See PROTOCOL.agent, section 2.5.2.
type identitiesAnswerAgentMsg struct {
	NumKeys uint32
	Keys    []byte `ssh:"rest"`
}

// See PROTOCOL.agent, section 2.6.2.
type signRequestAgentMsg struct {
	KeyBlob []byte
	Data    []byte
	Flags   uint32
}

// See PROTOCOL.agent, section 2.6.2.
type signResponseAgentMsg struct {
	SigBlob []byte
}

// AgentKey represents a protocol 2 key as defined in PROTOCOL.agent,
// section 2.5.2.
type AgentKey struct {
	blob    []byte
	Comment string
}

// String returns the storage form of an agent key with the format, base64
// encoded serialized key, and the comment if it is not empty.
func (ak *AgentKey) String() string {
	algo, _, ok := parseString(ak.blob)
	if !ok {
		return "malformed key"
	}

	algoName := string(algo)
	b64EncKey := base64.StdEncoding.EncodeToString(ak.blob)
	comment := ""

	if ak.Comment != "" {
		comment = " " + ak.Comment
	}

	return fmt.Sprintf("%s %s%s", algoName, b64EncKey, comment)
}

// Key returns an agent's public key as a *rsa.PublicKey, *dsa.PublicKey, or
// *OpenSSHCertV01.
func (ak *AgentKey) Key() (interface{}, error) {
	if key, _, ok := parsePubKey(ak.blob); ok {
		return key, nil
	}
	return nil, errors.New("ssh: failed to parse key blob")
}

func parseAgentKey(in []byte) (out *AgentKey, rest []byte, ok bool) {
	ak := new(AgentKey)

	if ak.blob, in, ok = parseString(in); !ok {
		return
	}

	comment, in, ok := parseString(in)
	if !ok {
		return
	}
	ak.Comment = string(comment)

	return ak, in, true
}

// AgentClient provides a means to communicate with an ssh agent process based
// on the protocol described in PROTOCOL.agent?rev=1.6.  It contains an
// embedded io.ReadWriter that is typically represented by using a *net.UnixConn.
type AgentClient struct {
	io.ReadWriter
}

func (ac *AgentClient) sendRequest(req []byte) error {
	msg := make([]byte, stringLength(req))
	marshalString(msg, req)
	if _, err := ac.Write(msg); err != nil {
		return err
	}
	return nil
}

func (ac *AgentClient) readResponse() ([]byte, error) {
	var respSizeBuf [4]byte
	if _, err := io.ReadFull(ac, respSizeBuf[:]); err != nil {
		return nil, err
	}

	respSize, _, ok := parseUint32(respSizeBuf[:])
	if !ok {
		return nil, errors.New("ssh: failure to parse response size")
	}

	buf := make([]byte, respSize)
	if _, err := io.ReadFull(ac, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// RequestIdentities queries the agent for protocol 2 keys as defined in
// PROTOCOL.agent section 2.5.2.
func (ac *AgentClient) RequestIdentities() ([]*AgentKey, error) {
	req := marshal(agentRequestIdentities, requestIdentitiesAgentMsg{})
	if err := ac.sendRequest(req); err != nil {
		return nil, err
	}

	resp, err := ac.readResponse()
	if err != nil {
		return nil, err
	}

	switch msg := decodeAgentMsg(resp).(type) {
	case *identitiesAnswerAgentMsg:
		keys := make([]*AgentKey, msg.NumKeys)
		data := msg.Keys[:]
		for i := uint32(0); i < msg.NumKeys; i++ {
			var key *AgentKey
			var ok bool
			if key, data, ok = parseAgentKey(data); !ok {
				return nil, ParseError{agentIdentitiesAnswer}
			}
			keys[i] = key
		}
		return keys, nil
	case *failureAgentMsg:
		return nil, errors.New("ssh: failed to list keys.")
	case ParseError, UnexpectedMessageError:
		return nil, msg.(error)
	}
	return nil, UnexpectedMessageError{agentIdentitiesAnswer, resp[0]}
}

// SignRequest requests the signing of data by the agent using a protocol 2 key
// as defined in PROTOCOL.agent section 2.6.2.  Supported key types include
// *rsa.PublicKey, *dsa.PublicKey, *OpenSSHCertV01.
func (ac *AgentClient) SignRequest(key interface{}, data []byte) ([]byte, error) {
	req := marshal(agentSignRequest, signRequestAgentMsg{
		KeyBlob: serializePublickey(key),
		Data:    data,
	})
	if err := ac.sendRequest(req); err != nil {
		return nil, err
	}

	resp, err := ac.readResponse()
	if err != nil {
		return nil, err
	}

	switch msg := decodeAgentMsg(resp).(type) {
	case *signResponseAgentMsg:
		return msg.SigBlob, nil
	case *failureAgentMsg:
		return nil, errors.New("ssh: failed to sign challenge")
	case ParseError, UnexpectedMessageError:
		return nil, msg.(error)
	}
	return nil, UnexpectedMessageError{agentSignResponse, resp[0]}
}

func decodeAgentMsg(packet []byte) interface{} {
	if len(packet) < 1 {
		return ParseError{0}
	}
	var msg interface{}
	switch packet[0] {
	case agentFailure:
		msg = new(failureAgentMsg)
	case agentSuccess:
		msg = new(successAgentMsg)
	case agentIdentitiesAnswer:
		msg = new(identitiesAnswerAgentMsg)
	case agentSignResponse:
		msg = new(signResponseAgentMsg)
	default:
		return UnexpectedMessageError{0, packet[0]}
	}
	if err := unmarshal(msg, packet, packet[0]); err != nil {
		return err
	}
	return msg
}
