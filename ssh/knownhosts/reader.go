package knownhosts

import (
	"io"

	"golang.org/x/crypto/ssh"
)

func NewFromReader(r io.Reader) (ssh.HostKeyCallback, error) {
	db := newHostKeyDB()
	if err := db.Read(r, ""); err != nil {
		return nil, err
	}

	var certChecker ssh.CertChecker
	certChecker.IsHostAuthority = db.IsHostAuthority
	certChecker.IsRevoked = db.IsRevoked
	certChecker.HostKeyFallback = db.check

	return certChecker.CheckHostKey, nil
}
