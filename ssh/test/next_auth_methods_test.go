package test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"testing"
)

func generateSigner() (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func handleChannels(chans <-chan ssh.NewChannel) {
	// Service the incoming Channel channel in go routine
	for newChannel := range chans {
		go handleChannel(newChannel)
	}
}

func handleChannel(newChan ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChan.ChannelType(); t != "session" {
		newChan.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	ch, reqs, err := newChan.Accept()
	if err != nil {
		return
	}
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			go func(ch ssh.Channel) {
				ch.Write([]byte("Hello world \r\n"))
				ch.Close()
			}(ch)
		}
	}
}

func runDemoServer(conf *ssh.ServerConfig) net.Listener {
	listener, err := net.Listen("tcp", "0.0.0.0:2200")
	if err != nil {
		log.Fatal("Failed to listen on 2200", err)
	}
	log.Print("Listening on :2200")
	go func() {
		for {
			tcpConn, err := listener.Accept()
			if err != nil {
				if _, ok := err.(net.Error); ok{
					return
				}
				log.Printf("Failed to accept incoming connection (%s)", err)
				continue
			}
			// Before use, a handshake must be performed on the incoming net.Conn.
			sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, conf)
			if err != nil {
				log.Printf("Failed to handshake (%s)", err)
				continue
			}

			log.Printf("New SSH connection from %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())
			// Discard all global out-of-band Requests
			go ssh.DiscardRequests(reqs)
			// Accept all channels
			go handleChannels(chans)
		}
	}()
	return listener
}

func originPasswordCallback(conn ssh.ConnMetadata, password []byte) (permissions *ssh.Permissions, e error) {
	if conn.User() == "foo" && string(password) == "bar" {
		return &ssh.Permissions{}, nil
	}
	e = errors.New("password not match")
	return
}

func originKeyboardInteractiveCallback(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (permissions *ssh.Permissions, e error) {
	answers, e := client("foo", "Write MFA code ", []string{"> "}, []bool{true})
	if e != nil {
		return
	}
	if len(answers) != 1 {
		e = errors.New("no mfa input")
		return
	}
	if answers[0] != "123456" {
		e = errors.New("mfa code not match")
	}
	return
}


func TestGeneralRun(t *testing.T) {
	signer, err := generateSigner()
	if err != nil {
		t.Error("Generate signer error", err)
	}
	serverConf := &ssh.ServerConfig{
		PasswordCallback: originPasswordCallback,
		KeyboardInteractiveCallback: originKeyboardInteractiveCallback,
	}
	serverConf.AddHostKey(signer)
	l := runDemoServer(serverConf)
	defer l.Close()

	var authMethods []ssh.AuthMethod
	var clientConfig *ssh.ClientConfig
	var client *ssh.Client

	// Error password
	authMethods = []ssh.AuthMethod{ssh.Password("bar123")}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err == nil {
		t.Error("Password not right, but connected")
		return
	}

	// Right password
	authMethods = []ssh.AuthMethod{ssh.Password("bar")}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err != nil {
		t.Error("General password connect ssh server error: ", err)
		return
	}
	client.Close()

	// Error keyboard interactive code response
	keyboardInteractiveChallenge := func(user, instruction string, questions []string, echos []bool, ) (answers []string, err error) {
		if len(questions) == 0 {
			return []string{}, nil
		}
		return []string{"12345678"}, nil
	}
	authMethods = []ssh.AuthMethod{ssh.KeyboardInteractive(keyboardInteractiveChallenge)}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err == nil {
		t.Error("Interactive code not right, but connected")
		return
	}

	// Right keyboard interactive code response
	keyboardInteractiveChallenge = func(user, instruction string, questions []string, echos []bool, ) (answers []string, err error) {
		if len(questions) == 0 {
			return []string{}, nil
		}
		return []string{"123456"}, nil
	}
	authMethods = []ssh.AuthMethod{ssh.KeyboardInteractive(keyboardInteractiveChallenge)}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err != nil {
		t.Error("General keyboard interactive connect ssh server error: ", err)
		return
	}
	client.Close()
}

func nextPasswordCallback(conn ssh.ConnMetadata, password []byte) (permissions *ssh.Permissions, e error) {
	if conn.User() == "foo" && string(password) == "bar" {
		return &ssh.Permissions{}, ssh.ErrPartialSuccess
	}
	e = errors.New("password not match")
	return
}

func TestNextAuthMethods(t *testing.T) {
	signer, err := generateSigner()
	if err != nil {
		t.Error("Generate signer error", err)
	}
	serverConf := &ssh.ServerConfig{
		PasswordCallback: nextPasswordCallback,
		KeyboardInteractiveCallback: originKeyboardInteractiveCallback,
		NextAuthMethodsCallback: func(conn ssh.ConnMetadata) []string {
			return []string{"keyboard-interactive"}
		},
	}
	serverConf.AddHostKey(signer)
	l := runDemoServer(serverConf)
	defer l.Close()

	var authMethods []ssh.AuthMethod
	var clientConfig *ssh.ClientConfig
	var client *ssh.Client
	var keyboardInteractiveChallenge ssh.KeyboardInteractiveChallenge

	// Error password
	authMethods = []ssh.AuthMethod{ssh.Password("bar123")}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err == nil {
		t.Error("Password not right, but connected")
		return
	}

	// Right password, but should not login success
	authMethods = []ssh.AuthMethod{ssh.Password("bar")}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err == nil {
		t.Error("Password right but should not connect, because we set partial success ")
		return
	}

	// Error keyboard interactive code response
	keyboardInteractiveChallenge = func(user, instruction string, questions []string, echos []bool, ) (answers []string, err error) {
		if len(questions) == 0 {
			return []string{}, nil
		}
		return []string{"12345678"}, nil
	}
	authMethods = []ssh.AuthMethod{ssh.KeyboardInteractive(keyboardInteractiveChallenge)}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err == nil {
		t.Error("Interactive code not right, but connected")
		return
	}

	// Right keyboard interactive code response, but should not login success
	keyboardInteractiveChallenge = func(user, instruction string, questions []string, echos []bool, ) (answers []string, err error) {
		if len(questions) == 0 {
			return []string{}, nil
		}
		return []string{"123456"}, nil
	}
	authMethods = []ssh.AuthMethod{ssh.KeyboardInteractive(keyboardInteractiveChallenge)}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	_, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err == nil {
		t.Error("Interactive code right but should not connect, because interactive code in next methods", err)
		return
	}

	// Right password and with right keyboard interactive code
	keyboardInteractiveChallenge = func(user, instruction string, questions []string, echos []bool, ) (answers []string, err error) {
		if len(questions) == 0 {
			return []string{}, nil
		}
		return []string{"123456"}, nil
	}
	authMethods = []ssh.AuthMethod{ssh.KeyboardInteractive(keyboardInteractiveChallenge), ssh.Password("bar")}
	clientConfig = &ssh.ClientConfig{User: "foo", Auth:authMethods, HostKeyCallback: ssh.InsecureIgnoreHostKey()}
	client, err = ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", "2200"), clientConfig)
	if err != nil {
		t.Error("Password and interactive code right but connect error", err)
		return
	}
	client.Close()
}




