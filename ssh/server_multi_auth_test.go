// Copyright 2020 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
)

func doClientServerAuth(t *testing.T, serverConfig *ServerConfig, clientConfig *ClientConfig, serverAuthErrors *[]error) error {
	c1, c2, err := netPipe()
	if err != nil {
		t.Fatalf("netPipe: %v", err)
	}
	defer c1.Close()
	defer c2.Close()

	serverConfig.AddHostKey(testSigners["rsa"])
	serverConfig.AuthLogCallback = func(conn ConnMetadata, method string, err error) {
		*serverAuthErrors = append(*serverAuthErrors, err)
	}
	go newServer(c1, serverConfig)
	_, _, _, err = NewClientConn(c2, "", clientConfig)
	return err
}

func TestMultiStepAuthKeyAndPwd(t *testing.T) {
	var serverAuthErrors []error
	username := "testuser"
	errPwdAuthFailed := errors.New("password auth failed")
	errWrongSequence := errors.New("wrong sequence")

	serverConfig := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, pass []byte) (*Permissions, error) {
			// we only accept password auth if public key auth was already completed
			if len(conn.PartialSuccessMethods()) == 0 {
				return nil, errWrongSequence
			}
			if conn.PartialSuccessMethods()[0] != "publickey" {
				return nil, errWrongSequence
			}
			if conn.User() == username && string(pass) == clientPassword {
				return nil, nil
			}
			return nil, errPwdAuthFailed
		},
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			if conn.User() == username && bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				// we only accept public key auth if it is the first authentication step
				if len(conn.PartialSuccessMethods()) == 0 {
					return nil, ErrPartialSuccess
				}
				return nil, errWrongSequence
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
		NextAuthMethodsCallback: func(conn ConnMetadata) []string {
			if len(conn.PartialSuccessMethods()) == 1 && conn.PartialSuccessMethods()[0] == "publickey" {
				return []string{"password"}
			}
			return []string{"publickey", "password"}
		},
	}

	clientConfig := &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			Password(clientPassword),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	err := doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}
	// the error sequence is:
	// - no auth passed yet
	// - partial success
	// - nil
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}

	// now test a wrong sequence
	serverAuthErrors = nil
	clientConfig.Auth = []AuthMethod{
		Password(clientPassword),
		PublicKeys(testSigners["rsa"]),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err == nil {
		t.Fatal("client login with wrong sequence must fail")
	}
	// the error sequence is:
	// - no auth passed yet
	// - wrong sequence
	// - partial success
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != errWrongSequence {
		t.Fatal("server not wrong sequence")
	}
	if serverAuthErrors[2] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}

	// now test using a correct sequence but a wrong password before the right one
	serverAuthErrors = nil
	n := 0
	passwords := []string{"WRONG", "WRONG", clientPassword}
	clientConfig.Auth = []AuthMethod{
		PublicKeys(testSigners["rsa"]),
		RetryableAuthMethod(PasswordCallback(func() (string, error) {
			p := passwords[n]
			n++
			return p, nil
		}), 3),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}
	// the error sequence is:
	// - no auth passed yet
	// - partial success
	// - wrong password
	// - wrong password
	// - nil
	if len(serverAuthErrors) != 5 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}
	if serverAuthErrors[2] != errPwdAuthFailed {
		t.Fatal("server not returned password authentication failed")
	}
	if serverAuthErrors[3] != errPwdAuthFailed {
		t.Fatal("server not returned password authentication failed")
	}
}

func TestMultiStepAuthKeyAndKeyboardInteractive(t *testing.T) {
	var serverAuthErrors []error
	username := "testuser"
	answers := keyboardInteractive(map[string]string{
		"question1": "answer1",
		"question2": "answer2",
	})
	errKeyboardIntAuthFailed := errors.New("keyboard-interactive auth failed")
	errWrongSequence := errors.New("wrong sequence")

	serverConfig := &ServerConfig{
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			if conn.User() == username && bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				// we only accept public key auth if it is the first authentication step
				if len(conn.PartialSuccessMethods()) == 0 {
					return nil, ErrPartialSuccess
				}
				return nil, errWrongSequence
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
		KeyboardInteractiveCallback: func(conn ConnMetadata, challenge KeyboardInteractiveChallenge) (*Permissions, error) {
			// we only accept keyboard-interactive auth if public key auth was already completed
			if len(conn.PartialSuccessMethods()) == 0 {
				return nil, errWrongSequence
			}
			if conn.PartialSuccessMethods()[0] != "publickey" {
				return nil, errWrongSequence
			}
			ans, err := challenge("user",
				"instruction",
				[]string{"question1", "question2"},
				[]bool{true, true})
			if err != nil {
				return nil, err
			}
			ok := conn.User() == username && ans[0] == "answer1" && ans[1] == "answer2"
			if ok {
				challenge("user", "motd", nil, nil)
				return nil, nil
			}
			return nil, errKeyboardIntAuthFailed
		},
		NextAuthMethodsCallback: func(conn ConnMetadata) []string {
			if len(conn.PartialSuccessMethods()) == 1 && conn.PartialSuccessMethods()[0] == "publickey" {
				return []string{"keyboard-interactive"}
			}
			return []string{"publickey", "keyboard-interactive"}
		},
	}

	clientConfig := &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			KeyboardInteractive(answers.Challenge),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	err := doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}
	// the error sequence is:
	// - no auth passed yet
	// - partial success
	// - nil
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}

	// now test a wrong sequence
	serverAuthErrors = nil
	clientConfig.Auth = []AuthMethod{
		KeyboardInteractive(answers.Challenge),
		PublicKeys(testSigners["rsa"]),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err == nil {
		t.Fatal("client login with wrong sequence must fail")
	}
	// the error sequence is:
	// - no auth passed yet
	// - wrong sequence
	// - partial success
	if len(serverAuthErrors) != 3 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != errWrongSequence {
		t.Fatal("server not wrong sequence")
	}
	if serverAuthErrors[2] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}

	// now test using a correct sequence but a wrong interactive answer before the right one
	serverAuthErrors = nil
	n := 0
	answersList := [][]string{
		{"WRONG", "WRONG"},
		{"answer2", "answer1"},
		{"answer1", "answer2"},
	}
	clientConfig.Auth = []AuthMethod{
		PublicKeys(testSigners["rsa"]),
		RetryableAuthMethod(KeyboardInteractiveChallenge(
			func(user, instruction string, questions []string, echos []bool) (answers []string, err error) {
				// after successful authentication we get a challeng with no questions
				if len(questions) == 0 {
					return nil, nil
				}
				result := answersList[n]
				n++
				return result, nil
			}), 3),
	}

	err = doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}
	// the error sequence is:
	// - no auth passed yet
	// - partial success
	// - keyboard-interactive auth failed
	// - keyboard-interactive auth failed
	// - nil
	if len(serverAuthErrors) != 5 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}
	if serverAuthErrors[2] != errKeyboardIntAuthFailed {
		t.Fatal("server not returned keyboard-interactive authentication failed")
	}
	if serverAuthErrors[3] != errKeyboardIntAuthFailed {
		t.Fatal("server not returned keyboard-interactive authentication failed")
	}
}

func TestMultiStepAuthKeyAndPwdAndKeyboardInteractive(t *testing.T) {
	var serverAuthErrors []error
	username := "testuser"
	answers := keyboardInteractive(map[string]string{
		"question1": "answer1",
		"question2": "answer2",
	})
	errKeyboardIntAuthFailed := errors.New("keyboard-interactive auth failed")
	errPwdAuthFailed := errors.New("password auth failed")
	errWrongSequence := errors.New("wrong sequence")

	serverConfig := &ServerConfig{
		PasswordCallback: func(conn ConnMetadata, pass []byte) (*Permissions, error) {
			// we only accept password auth if public key auth was already completed
			if len(conn.PartialSuccessMethods()) == 0 {
				return nil, errWrongSequence
			}
			if conn.PartialSuccessMethods()[0] != "publickey" {
				return nil, errWrongSequence
			}
			if conn.User() == username && string(pass) == clientPassword {
				return nil, ErrPartialSuccess
			}
			return nil, errPwdAuthFailed
		},
		PublicKeyCallback: func(conn ConnMetadata, key PublicKey) (*Permissions, error) {
			if conn.User() == username && bytes.Equal(key.Marshal(), testPublicKeys["rsa"].Marshal()) {
				// we only accept public key auth if it is the first authentication step
				if len(conn.PartialSuccessMethods()) == 0 {
					return nil, ErrPartialSuccess
				}
				return nil, errWrongSequence
			}

			return nil, fmt.Errorf("pubkey for %q not acceptable", conn.User())
		},
		KeyboardInteractiveCallback: func(conn ConnMetadata, challenge KeyboardInteractiveChallenge) (*Permissions, error) {
			// we only accept keyboard-interactive auth if public key auth and password auth were already completed
			if len(conn.PartialSuccessMethods()) <= 1 {
				return nil, errWrongSequence
			}
			if conn.PartialSuccessMethods()[0] != "publickey" {
				return nil, errWrongSequence
			}
			if conn.PartialSuccessMethods()[1] != "password" {
				return nil, errWrongSequence
			}
			ans, err := challenge("user",
				"instruction",
				[]string{"question1", "question2"},
				[]bool{true, true})
			if err != nil {
				return nil, err
			}
			ok := conn.User() == username && ans[0] == "answer1" && ans[1] == "answer2"
			if ok {
				challenge("user", "motd", nil, nil)
				return nil, nil
			}
			return nil, errKeyboardIntAuthFailed
		},
		NextAuthMethodsCallback: func(conn ConnMetadata) []string {
			if len(conn.PartialSuccessMethods()) == 1 && conn.PartialSuccessMethods()[0] == "publickey" {
				return []string{"password", "keyboard-interactive"}
			}
			if len(conn.PartialSuccessMethods()) == 2 && conn.PartialSuccessMethods()[0] == "publickey" &&
				conn.PartialSuccessMethods()[1] == "password" {
				return []string{"keyboard-interactive"}
			}
			return []string{"publickey", "password", "keyboard-interactive"}
		},
	}

	clientConfig := &ClientConfig{
		User: username,
		Auth: []AuthMethod{
			PublicKeys(testSigners["rsa"]),
			Password(clientPassword),
			KeyboardInteractive(answers.Challenge),
		},
		HostKeyCallback: InsecureIgnoreHostKey(),
	}

	err := doClientServerAuth(t, serverConfig, clientConfig, &serverAuthErrors)
	if err != nil {
		t.Fatalf("client login error: %s", err)
	}

	// the error sequence is:
	// - no auth passed yet
	// - partial success
	// - partial success
	// - nil
	if len(serverAuthErrors) != 4 {
		t.Fatalf("unexpected number of server auth errors: %v, errors: %+v", len(serverAuthErrors), serverAuthErrors)
	}
	if serverAuthErrors[1] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}
	if serverAuthErrors[2] != ErrPartialSuccess {
		t.Fatal("server not returned partial success")
	}
}
