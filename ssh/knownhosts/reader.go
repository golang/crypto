package knownhosts

import (
	"io"

	"golang.org/x/crypto/ssh"
)

// NewFromReader creates a host key callback from the given OpenSSH host io.Reader
// which is in SSH_KNOWN_HOSTS_FILE_FORMAT. The returned callback is for use in
// ssh.ClientConfig.HostKeyCallback. By preference, the key check
// operates on the hostname if available, i.e. if a server changes its
// IP address, the host key check will still succeed, even though a
// record of the new IP address is not available.
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
