// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestPreAuthUserCallback(t *testing.T) {
	rejected := errors.New("private policy rejection")
	for _, test := range []struct {
		name      string
		callback  bool
		reject    bool
		password  string
		wantCalls int
	}{
		{"unset", false, false, "password", 0},
		{"allowed", true, false, "password", 2},
		{"rejected", true, true, "password", 1},
		{"allowed with wrong password", true, false, "wrong", 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverNet, clientNet, err := netPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer serverNet.Close()
			defer clientNet.Close()

			calls, passwordCalls := 0, 0
			config := &ServerConfig{
				PasswordCallback: func(conn ConnMetadata, password []byte) (*Permissions, error) {
					passwordCalls++
					if test.callback && calls != 2 {
						t.Error("password callback ran before the policy check")
					}
					if string(password) != "password" {
						return nil, errors.New("wrong password")
					}
					return nil, nil
				},
			}
			if test.callback {
				config.PreAuthUserCallback = func(conn ConnMetadata) error {
					calls++
					if conn.User() != "user" || conn.RemoteAddr().String() != serverNet.RemoteAddr().String() || len(conn.SessionID()) == 0 {
						t.Error("pre-authentication callback received incorrect connection metadata")
					}
					if test.reject {
						return rejected
					}
					return nil
				}
			}
			config.AddHostKey(testSigners["ed25519"])
			done := make(chan error, 1)
			go func() {
				conn, _, _, err := NewServerConn(serverNet, config)
				if err == nil {
					conn.Close()
				}
				done <- err
			}()
			prompted := false
			client, _, _, clientErr := NewClientConn(clientNet, "", &ClientConfig{
				User: "user", HostKeyCallback: InsecureIgnoreHostKey(),
				Auth: []AuthMethod{PasswordCallback(func() (string, error) {
					prompted = true
					return test.password, nil
				})},
			})
			if clientErr == nil {
				client.Close()
			}
			clientNet.Close()
			serverErr := <-done
			wantFailure := test.reject || test.password != "password"
			if (clientErr != nil) != wantFailure || (serverErr != nil) != wantFailure {
				t.Fatalf("client error = %v, server error = %v; want failure = %v", clientErr, serverErr, wantFailure)
			}
			if calls != test.wantCalls {
				t.Errorf("policy calls = %d, want %d", calls, test.wantCalls)
			}
			if test.reject {
				if prompted || passwordCalls != 0 {
					t.Error("rejected connection reached password authentication")
				}
				if !strings.Contains(clientErr.Error(), "reason 1:") || !strings.Contains(clientErr.Error(), "host not allowed to connect") || strings.Contains(clientErr.Error(), rejected.Error()) {
					t.Errorf("client did not receive the fixed disconnect message: %v", clientErr)
				}
				var authErr *ServerAuthError
				if !errors.As(serverErr, &authErr) || !slices.Contains(authErr.Errors, rejected) {
					t.Errorf("server did not retain the policy error: %v", serverErr)
				}
			} else if !prompted || passwordCalls != 1 {
				t.Error("allowed connection did not follow normal password authentication")
			}
		})
	}
}

func TestPreAuthUserCallbackEachRequest(t *testing.T) {
	password := Marshal(struct {
		Change   bool
		Password string
	}{false, "password"})
	for _, test := range []struct {
		name     string
		requests []userAuthRequestMsg
	}{
		{"password without none", []userAuthRequestMsg{{User: "user", Method: "password", Payload: password}}},
		{"repeated user", []userAuthRequestMsg{{User: "user", Method: "none"}, {User: "user", Method: "none"}}},
		{"changed user", []userAuthRequestMsg{{User: "first", Method: "none"}, {User: "second", Method: "none"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			// Exercise the authentication loop over a real SSH transport, with
			// request sequences the normal client does not send.
			client, server, err := handshakePair(&ClientConfig{HostKeyCallback: InsecureIgnoreHostKey()}, "", false)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			defer server.Close()
			rejected := errors.New("private policy rejection")
			var users []string
			config := &ServerConfig{
				PreAuthUserCallback: func(conn ConnMetadata) error {
					users = append(users, conn.User())
					if len(users) == len(test.requests) {
						return rejected
					}
					return nil
				},
				PasswordCallback: func(ConnMetadata, []byte) (*Permissions, error) {
					t.Error("password callback ran despite the policy rejection")
					return nil, errors.New("unexpected authentication")
				},
			}
			done := make(chan struct{})
			var serverErr error
			go func() {
				defer close(done)
				conn := &connection{transport: server}
				_, serverErr = conn.serverAuthenticate(config)
			}()
			defer func() {
				client.Close()
				server.Close()
				<-done
			}()
			for i, request := range test.requests {
				request.Service = serviceSSH
				if err := client.writePacket(Marshal(&request)); err != nil {
					t.Fatal(err)
				}
				packet, err := client.readPacket()
				if err == nil && len(packet) > 0 && packet[0] == msgExtInfo {
					packet, err = client.readPacket()
				}
				if i == len(test.requests)-1 {
					var disconnect *disconnectMsg
					if !errors.As(err, &disconnect) || disconnect.Reason != 1 || disconnect.Message != "host not allowed to connect" {
						t.Fatalf("got packet %x and error %v, want policy disconnect", packet, err)
					}
				} else {
					if err != nil {
						t.Fatal(err)
					}
					var failure userAuthFailureMsg
					if err := Unmarshal(packet, &failure); err != nil || !slices.Equal(failure.Methods, []string{"password"}) || failure.PartialSuccess {
						t.Fatalf("allowed probe returned %x, want the normal password offer", packet)
					}
				}
			}
			<-done
			var authErr *ServerAuthError
			if !errors.As(serverErr, &authErr) || !slices.Contains(authErr.Errors, rejected) {
				t.Fatalf("server did not retain the policy rejection: %v", serverErr)
			}
			if len(users) != len(test.requests) {
				t.Fatalf("policy called %d times for %d requests", len(users), len(test.requests))
			}
			for i, request := range test.requests {
				if users[i] != request.User {
					t.Errorf("request %d checked username %q, want %q", i, users[i], request.User)
				}
			}
		})
	}
}
