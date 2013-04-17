// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd linux netbsd openbsd

package test

// functional test harness for unix.

import (
	"bytes"
	"crypto"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"text/template"
	"time"

	"code.google.com/p/go.crypto/ssh"
)

const sshd_config = `
Protocol 2
HostKey {{.Dir}}/ssh_host_rsa_key
HostKey {{.Dir}}/ssh_host_dsa_key
HostKey {{.Dir}}/ssh_host_ecdsa_key
Pidfile {{.Dir}}/sshd.pid
#UsePrivilegeSeparation no
KeyRegenerationInterval 3600
ServerKeyBits 768
SyslogFacility AUTH
LogLevel DEBUG2
LoginGraceTime 120
PermitRootLogin no
StrictModes no
RSAAuthentication yes
PubkeyAuthentication yes
AuthorizedKeysFile	{{.Dir}}/authorized_keys
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
`

var (
	configTmpl template.Template
	sshd       string // path to sshd
	rsakey     *rsa.PrivateKey
)

func init() {
	template.Must(configTmpl.Parse(sshd_config))
	block, _ := pem.Decode([]byte(testClientPrivateKey))
	rsakey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)
}

type server struct {
	t          *testing.T
	cleanup    func() // executed during Shutdown
	configfile string
	cmd        *exec.Cmd
	output     bytes.Buffer // holds stderr from sshd process
}

func username() string {
	var username string
	if user, err := user.Current(); err == nil {
		username = user.Username
	} else {
		// user.Current() currently requires cgo. If an error is
		// returned attempt to get the username from the environment.
		log.Printf("user.Current: %v; falling back on $USER", err)
		username = os.Getenv("USER")
	}
	if username == "" {
		panic("Unable to get username")
	}
	return username
}

func clientConfig() *ssh.ClientConfig {
	kc := new(keychain)
	kc.keys = append(kc.keys, rsakey)
	config := &ssh.ClientConfig{
		User: username(),
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(kc),
		},
	}
	return config
}

func (s *server) Dial(config *ssh.ClientConfig) *ssh.ClientConn {
	s.cmd = exec.Command("sshd", "-f", s.configfile, "-i")
	stdin, err := s.cmd.StdinPipe()
	if err != nil {
		s.t.Fatal(err)
	}
	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		s.t.Fatal(err)
	}
	s.cmd.Stderr = os.Stderr // &s.output
	err = s.cmd.Start()
	if err != nil {
		s.t.FailNow()
		s.Shutdown()
		s.t.Fatal(err)
	}
	conn, err := ssh.Client(&client{stdin, stdout}, config)
	if err != nil {
		s.t.FailNow()
		s.Shutdown()
		s.t.Fatal(err)
	}
	return conn
}

func (s *server) Shutdown() {
	if s.cmd != nil && s.cmd.Process != nil {
		if err := s.cmd.Process.Kill(); err != nil {
			s.t.Error(err)
		}
		s.cmd.Wait()
	}
	if s.t.Failed() {
		// log any output from sshd process
		s.t.Log(s.output.String())
	}
	s.cleanup()
}

// client wraps a pair of Reader/WriteClosers to implement the
// net.Conn interface.
type client struct {
	io.WriteCloser
	io.Reader
}

func (c *client) LocalAddr() net.Addr              { return nil }
func (c *client) RemoteAddr() net.Addr             { return nil }
func (c *client) SetDeadline(time.Time) error      { return nil }
func (c *client) SetReadDeadline(time.Time) error  { return nil }
func (c *client) SetWriteDeadline(time.Time) error { return nil }

// newServer returns a new mock ssh server.
func newServer(t *testing.T) *server {
	dir, err := ioutil.TempDir("", "sshtest")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(dir, "sshd_config"))
	if err != nil {
		t.Fatal(err)
	}
	err = configTmpl.Execute(f, map[string]string{
		"Dir": dir,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	for k, v := range keys {
		f, err := os.OpenFile(filepath.Join(dir, k), os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(v)); err != nil {
			t.Fatal(err)
		}
		f.Close()
	}

	return &server{
		t:          t,
		configfile: f.Name(),
		cleanup: func() {
			if err := os.RemoveAll(dir); err != nil {
				t.Error(err)
			}
		},
	}
}

// keychain implements the ClientKeyring interface
type keychain struct {
	keys []interface{}
}

func (k *keychain) Key(i int) (interface{}, error) {
	if i < 0 || i >= len(k.keys) {
		return nil, nil
	}
	switch key := k.keys[i].(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	case *dsa.PrivateKey:
		return &key.PublicKey, nil
	}
	panic("unknown key type")
}

func (k *keychain) Sign(i int, rand io.Reader, data []byte) (sig []byte, err error) {
	hashFunc := crypto.SHA1
	h := hashFunc.New()
	h.Write(data)
	digest := h.Sum(nil)
	switch key := k.keys[i].(type) {
	case *rsa.PrivateKey:
		return rsa.SignPKCS1v15(rand, key, hashFunc, digest)
	}
	return nil, errors.New("ssh: unknown key type")
}

func (k *keychain) loadPEM(file string) error {
	buf, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return errors.New("ssh: no key found")
	}
	r, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	k.keys = append(k.keys, r)
	return nil
}
