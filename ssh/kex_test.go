// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// Key exchange tests.

import (
	"fmt"
	"net"
	"testing"
)

func pipe() (net.Conn, net.Conn, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	conn1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	conn2, err := l.Accept()
	if err != nil {
		conn1.Close()
		return nil, nil, err
	}
	l.Close()
	return conn1, conn2, nil
}

func testKexAlgorithm(algo string) error {
	crypto := CryptoConfig{
		KeyExchanges: []string{algo},
	}
	serverConfig := ServerConfig{
		PasswordCallback: func(conn *ServerConn, user, password string) bool {
			return password == "password"
		},
		Crypto: crypto,
	}

	if err := serverConfig.SetRSAPrivateKey([]byte(testServerPrivateKey)); err != nil {
		return fmt.Errorf("SetRSAPrivateKey: %v", err)
	}

	clientConfig := ClientConfig{
		User:   "user",
		Auth:   []ClientAuth{ClientAuthPassword(password("password"))},
		Crypto: crypto,
	}

	conn1, conn2, err := pipe()
	if err != nil {
		return err
	}

	defer conn1.Close()
	defer conn2.Close()

	server := Server(conn2, &serverConfig)
	serverHS := make(chan error, 1)
	go func() {
		serverHS <- server.Handshake()
	}()

	// Client runs the handshake.
	_, err = Client(conn1, &clientConfig)
	if err != nil {
		return fmt.Errorf("Client: %v", err)
	}

	if err := <-serverHS; err != nil {
		return fmt.Errorf("server.Handshake: %v", err)
	}

	// Here we could check that we now can send data between client &
	// server.
	return nil
}

func TestKexAlgorithms(t *testing.T) {
	for _, algo := range []string{kexAlgoECDH256, kexAlgoECDH384, kexAlgoECDH521, kexAlgoDH1SHA1, kexAlgoDH14SHA1} {
		if err := testKexAlgorithm(algo); err != nil {
			t.Errorf("algorithm %s: %v", algo, err)
		}
	}
}
