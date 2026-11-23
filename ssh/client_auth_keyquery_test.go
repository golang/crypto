// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"slices"
	"testing"
)

// scriptedServer is the server half of an authentication exchange, driven
// packet by packet. It sees every packet the client writes and answers with
// whatever its reply function returns, so a test can make a server behave in
// ways the real ServerConfig never does.
type scriptedServer struct {
	reply   func(packet []byte) [][]byte
	queue   [][]byte
	written [][]byte
}

func (s *scriptedServer) writePacket(packet []byte) error {
	s.written = append(s.written, slices.Clone(packet))
	s.queue = append(s.queue, s.reply(packet)...)
	return nil
}

func (s *scriptedServer) readPacket() ([]byte, error) {
	if len(s.queue) == 0 {
		return nil, io.EOF
	}
	packet := s.queue[0]
	s.queue = s.queue[1:]
	return packet, nil
}

func (s *scriptedServer) Close() error                        { return nil }
func (s *scriptedServer) getAlgorithms() NegotiatedAlgorithms { return NegotiatedAlgorithms{} }
func (s *scriptedServer) getSessionID() []byte                { return []byte("session") }
func (s *scriptedServer) waitSession() error                  { return nil }

// requestsOf lists the userauth requests the client sent, as method names; a
// public key request is "publickey" or "publickey+signature".
func (s *scriptedServer) requestsOf(t *testing.T) []string {
	t.Helper()
	var methods []string
	for _, packet := range s.written {
		if packet[0] != msgUserAuthRequest {
			continue
		}
		var request userAuthRequestMsg
		if err := Unmarshal(packet, &request); err != nil {
			t.Fatalf("unmarshal userauth request: %v", err)
		}
		method := request.Method
		if method == "publickey" && request.Payload[0] != 0 {
			method += "+signature"
		}
		methods = append(methods, method)
	}
	return methods
}

func newScriptedAuth(t *testing.T, queryAnswer []byte) (*scriptedServer, *connection) {
	t.Helper()
	server := &scriptedServer{}
	server.reply = func(packet []byte) [][]byte {
		switch packet[0] {
		case msgServiceRequest:
			return [][]byte{Marshal(&serviceAcceptMsg{Service: serviceUserAuth})}
		case msgUserAuthRequest:
			var request userAuthRequestMsg
			if err := Unmarshal(packet, &request); err != nil {
				t.Errorf("unmarshal userauth request: %v", err)
				return nil
			}
			switch request.Method {
			case "none":
				return [][]byte{Marshal(&userAuthFailureMsg{Methods: []string{"password", "publickey"}})}
			case "publickey":
				return [][]byte{queryAnswer}
			case "keyboard-interactive":
				var prompts []byte
				prompts = append(prompts, 0, 0, 0, 5)
				prompts = append(prompts, "Code:"...)
				prompts = append(prompts, 0)
				return [][]byte{Marshal(&userAuthInfoRequestMsg{Name: "MFA", Instruction: "Enter the code", NumPrompts: 1, Prompts: prompts})}
			}
		case msgUserAuthInfoResponse:
			return [][]byte{{msgUserAuthSuccess}}
		}
		t.Errorf("unexpected client packet %d", packet[0])
		return nil
	}
	return server, &connection{transport: server}
}

func scriptedKey(t *testing.T) Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// A server that holds the key enough for the first factor may answer the
// unsigned query with a failure carrying the partial success flag instead of
// SSH_MSG_USERAUTH_PK_OK. OpenSSH takes that as the method having succeeded
// and moves on to the methods listed; the client must not call the key
// rejected.
func TestClientAuthPublicKeyQueryAnsweredWithPartialSuccess(t *testing.T) {
	answer := Marshal(&userAuthFailureMsg{Methods: []string{"keyboard-interactive"}, PartialSuccess: true})
	server, conn := newScriptedAuth(t, answer)

	var asked []string
	config := &ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			PublicKeys(scriptedKey(t)),
			KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				asked = append(asked, questions...)
				return []string{"123456"}, nil
			}),
		},
	}
	if err := conn.clientAuthenticate(config); err != nil {
		t.Fatalf("clientAuthenticate: %v", err)
	}
	if !slices.Equal(asked, []string{"Code:"}) {
		t.Errorf("keyboard-interactive questions = %q, want the server's one question", asked)
	}
	want := []string{"none", "publickey", "keyboard-interactive"}
	if got := server.requestsOf(t); !slices.Equal(got, want) {
		t.Errorf("requests = %q, want %q: the key must not be signed when the query already settled it", got, want)
	}
}

// The partial success must reach AuthCallback, which is how a caller tells a
// key the server accepted from one it never offered.
func TestClientAuthPublicKeyQueryPartialSuccessReachesAuthCallback(t *testing.T) {
	answer := Marshal(&userAuthFailureMsg{Methods: []string{"keyboard-interactive"}, PartialSuccess: true})
	_, conn := newScriptedAuth(t, answer)

	var sawPartial bool
	config := &ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			PublicKeys(scriptedKey(t)),
			KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				return []string{"123456"}, nil
			}),
		},
		AuthCallback: func(auth *ClientAuthContext) (AuthMethod, error) {
			if slices.Contains(auth.PartialSuccessMethods, "publickey") {
				sawPartial = true
			}
			return nil, nil
		},
	}
	if err := conn.clientAuthenticate(config); err != nil {
		t.Fatalf("clientAuthenticate: %v", err)
	}
	if !sawPartial {
		t.Error("AuthCallback never saw publickey among the partial success methods")
	}
}

// A plain failure to the query is still a rejection: the key is not signed,
// and publickey is not recorded as having partially succeeded.
func TestClientAuthPublicKeyQueryRejectedStaysRejected(t *testing.T) {
	answer := Marshal(&userAuthFailureMsg{Methods: []string{"keyboard-interactive"}})
	server, conn := newScriptedAuth(t, answer)

	var sawPartial bool
	config := &ClientConfig{
		User: "user",
		Auth: []AuthMethod{
			PublicKeys(scriptedKey(t)),
			KeyboardInteractive(func(name, instruction string, questions []string, echos []bool) ([]string, error) {
				return nil, errors.New("declined")
			}),
		},
		AuthCallback: func(auth *ClientAuthContext) (AuthMethod, error) {
			if slices.Contains(auth.PartialSuccessMethods, "publickey") {
				sawPartial = true
			}
			return nil, nil
		},
	}
	if err := conn.clientAuthenticate(config); err == nil {
		t.Fatal("clientAuthenticate succeeded though the server rejected the key")
	}
	if sawPartial {
		t.Error("a rejected key was reported as partially successful")
	}
	if slices.Contains(server.requestsOf(t), "publickey+signature") {
		t.Error("client signed a key the server rejected")
	}
}
