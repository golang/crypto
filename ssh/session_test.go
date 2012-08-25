// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ssh

// Session tests.

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"testing"

	"code.google.com/p/go.crypto/ssh/terminal"
)

type serverType func(*serverChan, *testing.T)

// dial constructs a new test server and returns a *ClientConn.
func dial(handler serverType, t *testing.T) *ClientConn {
	pw := password("tiger")
	serverConfig.PasswordCallback = func(conn *ServerConn, user, pass string) bool {
		return user == "testuser" && pass == string(pw)
	}
	serverConfig.PublicKeyCallback = nil

	l, err := Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("unable to listen: %v", err)
	}
	go func() {
		defer l.Close()
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("Unable to accept: %v", err)
			return
		}
		defer conn.Close()
		if err := conn.Handshake(); err != nil {
			t.Errorf("Unable to handshake: %v", err)
			return
		}
		for {
			ch, err := conn.Accept()
			if err == io.EOF {
				return
			}
			// We sometimes get ECONNRESET rather than EOF.
			if _, ok := err.(*net.OpError); ok {
				return
			}
			if err != nil {
				t.Errorf("Unable to accept incoming channel request: %v", err)
				return
			}
			if ch.ChannelType() != "session" {
				ch.Reject(UnknownChannelType, "unknown channel type")
				continue
			}
			ch.Accept()
			go handler(ch.(*serverChan), t)
		}
		t.Log("done")
	}()

	config := &ClientConfig{
		User: "testuser",
		Auth: []ClientAuth{
			ClientAuthPassword(pw),
		},
	}

	c, err := Dial("tcp", l.Addr().String(), config)
	if err != nil {
		t.Fatalf("unable to dial remote side: %v", err)
	}
	return c
}

// Test a simple string is returned to session.Stdout.
func TestSessionShell(t *testing.T) {
	conn := dial(shellHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	stdout := new(bytes.Buffer)
	session.Stdout = stdout
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %s", err)
	}
	if err := session.Wait(); err != nil {
		t.Fatalf("Remote command did not exit cleanly: %v", err)
	}
	actual := stdout.String()
	if actual != "golang" {
		t.Fatalf("Remote shell did not return expected string: expected=golang, actual=%s", actual)
	}
}

// TODO(dfc) add support for Std{in,err}Pipe when the Server supports it.

// Test a simple string is returned via StdoutPipe.
func TestSessionStdoutPipe(t *testing.T) {
	conn := dial(shellHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("Unable to request StdoutPipe(): %v", err)
	}
	var buf bytes.Buffer
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	done := make(chan bool, 1)
	go func() {
		if _, err := io.Copy(&buf, stdout); err != nil {
			t.Errorf("Copy of stdout failed: %v", err)
		}
		done <- true
	}()
	if err := session.Wait(); err != nil {
		t.Fatalf("Remote command did not exit cleanly: %v", err)
	}
	<-done
	actual := buf.String()
	if actual != "golang" {
		t.Fatalf("Remote shell did not return expected string: expected=golang, actual=%s", actual)
	}
}

// Test non-0 exit status is returned correctly.
func TestExitStatusNonZero(t *testing.T) {
	conn := dial(exitStatusNonZeroHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	err = session.Wait()
	if err == nil {
		t.Fatalf("expected command to fail but it didn't")
	}
	e, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError but got %T", err)
	}
	if e.ExitStatus() != 15 {
		t.Fatalf("expected command to exit with 15 but got %v", e.ExitStatus())
	}
}

// Test 0 exit status is returned correctly.
func TestExitStatusZero(t *testing.T) {
	conn := dial(exitStatusZeroHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()

	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	err = session.Wait()
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

// Test exit signal and status are both returned correctly.
func TestExitSignalAndStatus(t *testing.T) {
	conn := dial(exitSignalAndStatusHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	err = session.Wait()
	if err == nil {
		t.Fatalf("expected command to fail but it didn't")
	}
	e, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError but got %T", err)
	}
	if e.Signal() != "TERM" || e.ExitStatus() != 15 {
		t.Fatalf("expected command to exit with signal TERM and status 15 but got signal %s and status %v", e.Signal(), e.ExitStatus())
	}
}

// Test exit signal and status are both returned correctly.
func TestKnownExitSignalOnly(t *testing.T) {
	conn := dial(exitSignalHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	err = session.Wait()
	if err == nil {
		t.Fatalf("expected command to fail but it didn't")
	}
	e, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError but got %T", err)
	}
	if e.Signal() != "TERM" || e.ExitStatus() != 143 {
		t.Fatalf("expected command to exit with signal TERM and status 143 but got signal %s and status %v", e.Signal(), e.ExitStatus())
	}
}

// Test exit signal and status are both returned correctly.
func TestUnknownExitSignal(t *testing.T) {
	conn := dial(exitSignalUnknownHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	err = session.Wait()
	if err == nil {
		t.Fatalf("expected command to fail but it didn't")
	}
	e, ok := err.(*ExitError)
	if !ok {
		t.Fatalf("expected *ExitError but got %T", err)
	}
	if e.Signal() != "SYS" || e.ExitStatus() != 128 {
		t.Fatalf("expected command to exit with signal SYS and status 128 but got signal %s and status %v", e.Signal(), e.ExitStatus())
	}
}

// Test WaitMsg is not returned if the channel closes abruptly.
func TestExitWithoutStatusOrSignal(t *testing.T) {
	conn := dial(exitWithoutSignalOrStatus, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	err = session.Wait()
	if err == nil {
		t.Fatalf("expected command to fail but it didn't")
	}
	_, ok := err.(*ExitError)
	if ok {
		// you can't actually test for errors.errorString
		// because it's not exported.
		t.Fatalf("expected *errorString but got %T", err)
	}
}

func TestInvalidServerMessage(t *testing.T) {
	conn := dial(sendInvalidRecord, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	// Make sure that we closed all the clientChans when the connection
	// failed.
	session.wait()

	defer session.Close()
}

// In the wild some clients (and servers) send zero sized window updates. 
// Test that the client can continue after receiving a zero sized update.
func TestClientZeroWindowAdjust(t *testing.T) {
	conn := dial(sendZeroWindowAdjust, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()

	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	err = session.Wait()
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

// In the wild some clients (and servers) send zero sized window updates. 
// Test that the server can continue after receiving a zero size update.
func TestServerZeroWindowAdjust(t *testing.T) {
	conn := dial(exitStatusZeroHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()

	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}

	// send a bogus zero sized window update
	session.clientChan.sendWindowAdj(0)

	err = session.Wait()
	if err != nil {
		t.Fatalf("expected nil but got %v", err)
	}
}

// Verify that the client never sends a packet larger than maxpacket.
func TestClientStdinRespectsMaxPacketSize(t *testing.T) {
	conn := dial(discardHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	// try to stuff 128k of data into a 32k hole.
	const size = 128 * 1024
	n, err := session.clientChan.stdin.Write(make([]byte, size))
	if n != size || err != nil {
		t.Fatalf("failed to write: %d, %v", n, err)
	}
}

// Verify that the client never accepts a packet larger than maxpacket.
func TestServerStdoutRespectsMaxPacketSize(t *testing.T) {
	conn := dial(largeSendHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	out, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("Unable to connect to Stdout: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	if _, err := ioutil.ReadAll(out); err != nil {
		t.Fatalf("failed to read: %v", err)
	}
}

func TestClientCannotSendAfterEOF(t *testing.T) {
	// TODO(dfc) currently writes succeed after Close()
	t.Logf("test skipped")
	return

	conn := dial(shellHandler, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	in, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("Unable to connect channel stdin: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	if err := in.Close(); err != nil {
		t.Fatalf("Unable to close stdin: %v", err)
	}
	if _, err := in.Write([]byte("foo")); err == nil {
		t.Fatalf("Session write should fail")
	}
}

func TestClientCannotSendAfterClose(t *testing.T) {
	conn := dial(exitWithoutSignalOrStatus, t)
	defer conn.Close()
	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("Unable to request new session: %v", err)
	}
	defer session.Close()
	in, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("Unable to connect channel stdin: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("Unable to execute command: %v", err)
	}
	// close underlying channel
	if err := session.channel.Close(); err != nil {
		t.Fatalf("Unable to close session: %v", err)
	}
	if _, err := in.Write([]byte("foo")); err == nil {
		t.Fatalf("Session write should fail")
	}
}

type exitStatusMsg struct {
	PeersId   uint32
	Request   string
	WantReply bool
	Status    uint32
}

type exitSignalMsg struct {
	PeersId    uint32
	Request    string
	WantReply  bool
	Signal     string
	CoreDumped bool
	Errmsg     string
	Lang       string
}

func newServerShell(ch *serverChan, prompt string) *ServerTerminal {
	term := terminal.NewTerminal(ch, prompt)
	return &ServerTerminal{
		Term:    term,
		Channel: ch,
	}
}

func exitStatusZeroHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	// this string is returned to stdout
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	sendStatus(0, ch, t)
}

func exitStatusNonZeroHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	sendStatus(15, ch, t)
}

func exitSignalAndStatusHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	sendStatus(15, ch, t)
	sendSignal("TERM", ch, t)
}

func exitSignalHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	sendSignal("TERM", ch, t)
}

func exitSignalUnknownHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	sendSignal("SYS", ch, t)
}

func exitWithoutSignalOrStatus(ch *serverChan, t *testing.T) {
	defer ch.Close()
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
}

func shellHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	// this string is returned to stdout
	shell := newServerShell(ch, "golang")
	readLine(shell, t)
	sendStatus(0, ch, t)
}

func readLine(shell *ServerTerminal, t *testing.T) {
	if _, err := shell.ReadLine(); err != nil && err != io.EOF {
		t.Fatalf("unable to read line: %v", err)
	}
}

func sendStatus(status uint32, ch *serverChan, t *testing.T) {
	msg := exitStatusMsg{
		PeersId:   ch.remoteId,
		Request:   "exit-status",
		WantReply: false,
		Status:    status,
	}
	if err := ch.writePacket(marshal(msgChannelRequest, msg)); err != nil {
		t.Errorf("unable to send status: %v", err)
	}
}

func sendSignal(signal string, ch *serverChan, t *testing.T) {
	sig := exitSignalMsg{
		PeersId:    ch.remoteId,
		Request:    "exit-signal",
		WantReply:  false,
		Signal:     signal,
		CoreDumped: false,
		Errmsg:     "Process terminated",
		Lang:       "en-GB-oed",
	}
	if err := ch.writePacket(marshal(msgChannelRequest, sig)); err != nil {
		t.Errorf("unable to send signal: %v", err)
	}
}

func sendInvalidRecord(ch *serverChan, t *testing.T) {
	defer ch.Close()
	packet := make([]byte, 1+4+4+1)
	packet[0] = msgChannelData
	marshalUint32(packet[1:], 29348723 /* invalid channel id */)
	marshalUint32(packet[5:], 1)
	packet[9] = 42

	if err := ch.writePacket(packet); err != nil {
		t.Errorf("unable send invalid record: %v", err)
	}
}

func sendZeroWindowAdjust(ch *serverChan, t *testing.T) {
	defer ch.Close()
	// send a bogus zero sized window update
	ch.sendWindowAdj(0)
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	sendStatus(0, ch, t)
}

func discardHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	// grow the window to avoid being fooled by
	// the initial 1 << 14 window.
	ch.sendWindowAdj(1024 * 1024)
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	io.Copy(ioutil.Discard, ch.serverConn)
}

func largeSendHandler(ch *serverChan, t *testing.T) {
	defer ch.Close()
	// grow the window to avoid being fooled by
	// the initial 1 << 14 window.
	ch.sendWindowAdj(1024 * 1024)
	shell := newServerShell(ch, "> ")
	readLine(shell, t)
	// try to send more than the 32k window
	// will allow
	if err := ch.writePacket(make([]byte, 128*1024)); err == nil {
		t.Errorf("wrote packet larger than 32k")
	}
}
