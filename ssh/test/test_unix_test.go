// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd linux netbsd openbsd

package test

// functional test harness for unix.

import (
	"crypto"
	"crypto/dsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
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

const (
	sshd_config = `
Protocol 2
HostKey {{.Dir}}/ssh_host_rsa_key
HostKey {{.Dir}}/ssh_host_dsa_key
HostKey {{.Dir}}/ssh_host_ecdsa_key
Pidfile {{.Dir}}/sshd.pid
#UsePrivilegeSeparation no
KeyRegenerationInterval 3600
ServerKeyBits 768
SyslogFacility AUTH
LogLevel INFO
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
	testClientPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxF/3T7uD5rb4Cty2vc4qAhA6yclK+sRCCuz6/qy4MnXKlk1P
5Le8O4CozsOL784B34ypdPQlsr4G/suXQok5PTMSPnqxjYbN6cGqEvhGrwG2sAe4
hKmMk3qd2GiSvuESeDl+2ZVzACDK0y/lFayvPbeeoQpBWGgIKN1WPs+q2/292wwW
LRNWNrUuwt2ru92g4Hm/abCK0lfOrnCgU5eV+thZ2IshnfvsQpyweri8YpjOTil3
y8yUDUv0MmcpNdoNw/MuvV8NRswkil9btfjEG6Mn9ByXBtq8lAix3XA1aaQKch8d
ji6ud4ZZEP8sXX5Q6gqgBOI/naGoErCHwtU9kwIDAQABAoIBAFJRKAp0QEZmTHPB
MZk+4r0asIoFpziXLFgIHu7C2DPOzK1Umzj1DCKlPB3wOqi7Ym2jOSWdcnAK2EPW
dAGgJC5TSkKGjAcXixmB5RkumfKidUI0+lQh/puTurcMnvcEwglDkLkEvMBA/sSo
Pw9m486rOgOnmNzGPyViItURmD2+0yDdLl/vOsO/L1p76GCd0q0J3LqnmsQmawi7
Zwj2Stm6BIrggG5GsF204Iet5219TYLo4g1Qb2AlJ9C8P1FtAWhMwJalDxH9Os2/
KCDjnaq5n3bXbIU+3QjskjeVXL/Fnbhjnh4zs1EA7eHzl9dCGbcZ2LOimo2PRo8q
wVQmz4ECgYEA9dhiu74TxRVoaO5N2X+FsMzRO8gZdP3Z9IrV4jVN8WT4Vdp0snoF
gkVkqqbQUNKUb5K6B3Js/qNKfcjLbCNq9fewTcT6WsHQdtPbX/QA6Pa2Z29wrlA2
wrIYaAkmVaHny7wsOmgX01aOnuf2MlUnksK43sjZHdIo/m+sDKwwY1cCgYEAzHx4
mwUDMdRF4qpDKJhthraBNejRextNQQYsHVnNaMwZ4aeQcH5l85Cgjm7VpGlbVyBQ
h4zwFvllImp3D2U3mjVkV8Tm9ID98eWvw2YDzBnS3P3SysajD23Z+BXSG9GNv/8k
oAm+bVlvnJy4haK2AcIMk1YFuDuAOmy73abk7iUCgYEAj4qVM1sq/eKfAM1LJRfg
/jbIX+hYfMePD8pUUWygIra6jJ4tjtvSBZrwyPb3IImjY3W/KoP0AcVjxAeORohz
dkP1a6L8LiuFxSuzpdW5BkyuebxGhXCOWKVVvMDC4jLTPVCUXlHSv3GFemCjjgXM
QlNxT5rjsha4Gr8nLIsJAacCgYA4VA1Q/pd7sXKy1p37X8nD8yAyvnh+Be5I/C9I
woUP2jFC9MqYAmmJJ4ziz2swiAkuPeuQ+2Tjnz2ZtmQnrIUdiJmkh8vrDGFnshKx
q7deELsCPzVCwGcIiAUkDra7DQWUHu9y2lxHePyC0rUNst2aLF8UcvzOXC2danhx
vViQtQKBgCmZ7YavE/GNWww8N3xHBJ6UPmUuhQlnAbgNCcdyz30MevBg/JbyUTs2
slftTH15QusJ1UoITnnZuFJ40LqDvh8UhiK09ffM/IbUx839/m2vUOdFZB/WNn9g
Cy0LzddU4KE8JZ/tlk68+hM5fjLLA0aqSunaql5CKfplwLu8x1hL
-----END RSA PRIVATE KEY-----
`
)

var keys = map[string]string{
	"ssh_host_dsa_key": `-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQDe2SIKvZdBp+InawtSXH0NotiMPhm3udyu4hh/E+icMz264kDX
v+sV7ddnSQGQWZ/eVU7Jtx29dCMD1VlFpEd7yGKzmdwJIeA+YquNWoqBRQEJsWWS
7Fsfvv83dA/DTNIQfOY3+TIs6Mb9vagbgQMU3JUWEhbLE9LCEU6UwwRlpQIVAL4p
JF83SwpE8Jx6KnDpR89npkl/AoGAAy00TdDnAXvStwrZiAFbjZi8xDmPa9WwpfhJ
Rkno45TthDLrS+WmqY8/LTwlqZdOBtoBAynMJfKkUiZM21lWWpL1hRKYdwBlIBy5
XdR2/6wcPSuZ0tCQhDBTstX0Q3P1j198KGKvzy7q9vILKQwtSRqLS1y4JJERafdO
E+9CnGwCgYBz0WwBe2EZtGhGhBdnelTIBeo7PIsr0PzqxQj+dc8PBl8K9FfhRyOp
U39stUvoUxE9vaIFrY1P5xENjLFnPf+hlcuf40GUWEssW9YWPOaBp8afa9hY5Sxs
pvNR6eZFEFOJnx/ZgcA4g+vbrgGi5cM0W470mbGw2CkfJQUafdoIgAIUF+2I9kZe
2FTBuC9uacqczDlc+0k=
-----END DSA PRIVATE KEY-----`,
	"ssh_host_rsa_key": `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAuf76Ue2Wtae9oDtaS6rIJgO7iCFTsZUTW9LBsvx/2nli6jKU
d9tUbBRzgdbnRLJ32UljXhERuB/axlrX8/lBzUZ+oYiM0KkEEOXY1z/bcMxdRxGF
XHuf4uXvyC2XyA4+ZvBeS4j1QFyIHZ62o7gAlKMTjiek3B4AQEJAlCLmhH3jB8wc
K/IYXAOlNGM5G44/ZLQpTi8diOV6DLs7tJ7rtEQedOEJfZng5rwp0USFkqcbfDbe
9/hk0J32jZvOtZNBokYtBb4YEdIiWBzzNtHzU3Dzw61+TKVXaH5HaIvzL9iMrw9f
kJbJyogfZk9BJfemEN+xqP72jlhE8LXNhpTxFQIDAQABAoIBAHbdf+Y5+5XuNF6h
b8xpwW2h9whBnDYiOnP1VfroKWFbMB7R4lZS4joMO+FfkP8zOyqvHwTvza4pFWys
g9SUmDvy8FyVYsC7MzEFYzX0xm3o/Te898ip7P1Zy4rXsGeWysSImwqU5X+TYx3i
33/zyNM1APtZVJ+jwK9QZ+sD/uPuZK2yS03HGSMZq6ebdoOSaYhluKrxXllSLO1J
KJxDiDdy2lEFw0W8HcI3ly1lg6OI+TRqqaCcLVNF4fNJmYIFM+2VEI9BdgynIh0Q
pMZlJKgaEBcSqCymnTK81ohYD1cV4st2B0km3Sw35Rl04Ij5ITeiya3hp8VfE6UY
PljkA6UCgYEA4811FTFj+kzNZ86C4OW1T5sM4NZt8gcz6CSvVnl+bDzbEOMMyzP7
2I9zKsR5ApdodH2m8d+RUw1Oe0bNGW5xig/DH/hn9lLQaO52JAi0we8A94dUUMSq
fUk9jKZEXpP/MlfTdJaPos9mxT7z8jREQxIiqH9AV0rLVDOCfDbSWj8CgYEA0QTE
IAUuki3UUqYKzLQrh/QmhY5KTx5amNW9XZ2VGtJvDPJrtBSBZlPEuXZAc4eBWEc7
U3Y9QwsalzupU6Yi6+gmofaXs8xJnj+jKth1DnJvrbLLGlSmf2Ijnwt22TyFUOtt
UAknpjHutDjQPf7pUGWaCPgwwKFsdB8EBjpJF6sCgYAfXesBQAvEK08dPBJJZVfR
3kenrd71tIgxLtv1zETcIoUHjjv0vvOunhH9kZAYC0EWyTZzl5UrGmn0D4uuNMbt
e74iaNHn2P9Zc3xQ+eHp0j8P1lKFzI6tMaiH9Vz0qOw6wl0bcJ/WizhbcI+migvc
MGMVUHBLlMDqly0gbWwJgQKBgQCgtb9ut01FjANSwORQ3L8Tu3/a9Lrh9n7GQKFn
V4CLrP1BwStavOF5ojMCPo/zxF6JV8ufsqwL3n/FhFP/QyBarpb1tTqTPiHkkR2O
Ffx67TY9IdnUFv4lt3mYEiKBiW0f+MSF42Qe/wmAfKZw5IzUCirTdrFVi0huSGK5
vxrwHQKBgHZ7RoC3I2f6F5fflA2ZAe9oJYC7XT624rY7VeOBwK0W0F47iV3euPi/
pKvLIBLcWL1Lboo+girnmSZtIYg2iLS3b4T9VFcKWg0y4AVwmhMWe9jWIltfWAAX
9l0lNikMRGAx3eXudKXEtbGt3/cUzPVaQUHy5LiBxkxnFxgaJPXs
-----END RSA PRIVATE KEY-----`,
	"ssh_host_ecdsa_key": `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINGWx0zo6fhJ/0EAfrPzVFyFC9s18lBt3cRoEDhS3ARooAoGCCqGSM49
AwEHoUQDQgAEi9Hdw6KvZcWxfg2IDhA7UkpDtzzt6ZqJXSsFdLd+Kx4S3Sx4cVO+
6/ZOXRnPmNAlLUqjShUsUBBngG0u2fqEqA==
-----END EC PRIVATE KEY-----`,
	"authorized_keys": `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDEX/dPu4PmtvgK3La9zioCEDrJyUr6xEIK7Pr+rLgydcqWTU/kt7w7gKjOw4vvzgHfjKl09CWyvgb+y5dCiTk9MxI+erGNhs3pwaoS+EavAbawB7iEqYyTep3YaJK+4RJ4OX7ZlXMAIMrTL+UVrK89t56hCkFYaAgo3VY+z6rb/b3bDBYtE1Y2tS7C3au73aDgeb9psIrSV86ucKBTl5X62FnYiyGd++xCnLB6uLximM5OKXfLzJQNS/QyZyk12g3D8y69Xw1GzCSKX1u1+MQboyf0HJcG2ryUCLHdcDVppApyHx2OLq53hlkQ/yxdflDqCqAE4j+doagSsIfC1T2T user@host`,
}

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
}

func (s *server) Dial() *ssh.ClientConn {
	s.cmd = exec.Command("sshd", "-f", s.configfile, "-i")
	stdin, err := s.cmd.StdinPipe()
	if err != nil {
		s.t.Fatal(err)
	}
	stdout, err := s.cmd.StdoutPipe()
	if err != nil {
		s.t.Fatal(err)
	}
	s.cmd.Stderr = os.Stderr
	err = s.cmd.Start()
	if err != nil {
		s.Shutdown()
		s.t.Fatal(err)
	}

	user, err := user.Current()
	if err != nil {
		s.Shutdown()
		s.t.Fatal(err)
	}
	kc := new(keychain)
	kc.keys = append(kc.keys, rsakey)
	config := &ssh.ClientConfig{
		User: user.Username,
		Auth: []ssh.ClientAuth{
			ssh.ClientAuthKeyring(kc),
		},
	}
	conn, err := ssh.Client(&client{stdin, stdout}, config)
	if err != nil {
		s.Shutdown()
		s.t.Fatal(err)
	}
	return conn
}

func (s *server) Shutdown() {
	if err := s.cmd.Process.Kill(); err != nil {
		s.t.Error(err)
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
