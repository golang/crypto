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
	configTmpl        template.Template
	rsakey            *rsa.PrivateKey
	serializedHostKey []byte
)

func init() {
	template.Must(configTmpl.Parse(sshd_config))
	block, _ := pem.Decode([]byte(testClientPrivateKey))
	rsakey, _ = x509.ParsePKCS1PrivateKey(block.Bytes)

	block, _ = pem.Decode([]byte(keys["ssh_host_rsa_key"]))
	if block == nil {
		panic("pem.Decode ssh_host_rsa_key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic("ParsePKCS1PrivateKey: " + err.Error())
	}
	serializedHostKey = ssh.MarshalPublicKey(ssh.NewRSAPublicKey(&priv.PublicKey))
}

type server struct {
	t          *testing.T
	cleanup    func() // executed during Shutdown
	configfile string
	cmd        *exec.Cmd
	output     bytes.Buffer // holds stderr from sshd process

	// Client half of the network connection.
	clientConn net.Conn
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

type storedHostKey struct {
	// keys map from an algorithm string to binary key data.
	keys map[string][]byte
}

func (k *storedHostKey) Add(algo string, public []byte) {
	if k.keys == nil {
		k.keys = map[string][]byte{}
	}
	k.keys[algo] = append([]byte(nil), public...)
}

func (k *storedHostKey) Check(addr string, remote net.Addr, algo string, key []byte) error {
	if k.keys == nil || bytes.Compare(key, k.keys[algo]) != 0 {
		return errors.New("host key mismatch")
	}
	return nil
}

func clientConfig() *ssh.ClientConfig {
	keyChecker := storedHostKey{}
	keyChecker.Add("ssh-rsa", serializedHostKey)

	kc := new(keychain)
	kc.keys = append(kc.keys, rsakey)
	config := &ssh.ClientConfig{
		User: username(),
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(kc),
		},
		HostKeyChecker: &keyChecker,
	}
	return config
}

// unixConnection creates two halves of a connected net.UnixConn.  It
// is used for connecting the Go SSH client with sshd without opening
// ports.
func unixConnection() (*net.UnixConn, *net.UnixConn, error) {
	dir, err := ioutil.TempDir("", "unixConnection")
	if err != nil {
		return nil, nil, err
	}
	defer os.Remove(dir)

	addr := filepath.Join(dir, "ssh")
	listener, err := net.Listen("unix", addr)
	if err != nil {
		return nil, nil, err
	}
	defer listener.Close()
	c1, err := net.Dial("unix", addr)
	if err != nil {
		return nil, nil, err
	}

	c2, err := listener.Accept()
	if err != nil {
		c1.Close()
		return nil, nil, err
	}

	return c1.(*net.UnixConn), c2.(*net.UnixConn), nil
}

func (s *server) TryDial(config *ssh.ClientConfig) (*ssh.ClientConn, error) {
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		s.t.Skipf("skipping test: %v", err)
	}

	c1, c2, err := unixConnection()
	if err != nil {
		s.t.Fatalf("unixConnection: %v", err)
	}

	s.cmd = exec.Command(sshd, "-f", s.configfile, "-i", "-e")
	f, err := c2.File()
	if err != nil {
		s.t.Fatalf("UnixConn.File: %v", err)
	}
	defer f.Close()
	s.cmd.Stdin = f
	s.cmd.Stdout = f
	s.cmd.Stderr = &s.output
	if err := s.cmd.Start(); err != nil {
		s.t.Fail()
		s.Shutdown()
		s.t.Fatalf("s.cmd.Start: %v", err)
	}
	s.clientConn = c1
	return ssh.Client(c1, config)
}

func (s *server) Dial(config *ssh.ClientConfig) *ssh.ClientConn {
	conn, err := s.TryDial(config)
	if err != nil {
		s.t.Fail()
		s.Shutdown()
		s.t.Fatalf("ssh.Client: %v", err)
	}
	return conn
}

func (s *server) Shutdown() {
	if s.cmd != nil && s.cmd.Process != nil {
		// Don't check for errors; if it fails it's most
		// likely "os: process already finished", and we don't
		// care about that. Use os.Interrupt, so child
		// processes are killed too.
		s.cmd.Process.Signal(os.Interrupt)
		s.cmd.Wait()
	}
	if s.t.Failed() {
		// log any output from sshd process
		s.t.Logf("sshd: %s", s.output.String())
	}
	s.cleanup()
}

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

func (k *keychain) Key(i int) (ssh.PublicKey, error) {
	if i < 0 || i >= len(k.keys) {
		return nil, nil
	}
	switch key := k.keys[i].(type) {
	case *rsa.PrivateKey:
		return ssh.NewRSAPublicKey(&key.PublicKey), nil
	case *dsa.PrivateKey:
		return ssh.NewDSAPublicKey(&key.PublicKey), nil
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
