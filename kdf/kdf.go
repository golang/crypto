package kdf

import (
	"encoding/binary"
	"crypto"
	"errors"
	"hash"
	"io"
	// Force registration of SHA1 and SHA2 families of cryptographic primitives to
	// reduce the burden on KDF consuming packages.
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
)

var (
	// ErrInvalidLengthParameter the KDF length parameter is invalid
	ErrInvalidLengthParameter = errors.New("invalid length parameter")

	// ErrInvalidSeedParameter a parameter is invalid.
	ErrInvalidSeedParameter = errors.New("invalid input parameter")
	)

// Verify KDF completely implements the io.Reader interface.
var _ io.Reader = &KDF{}

// KDF key derivation context struct
type KDF struct {
	seed       []byte
	other      []byte
	length     int
	iterations uint32
	position   int
	buffer     []byte
	digester   hash.Hash
}

// i2osp 4-byte integer marshalling.
func i2osp(i uint32) (osp []byte) {
	osp = make([]byte, 4)
	binary.BigEndian.PutUint32(osp, i)
	return
}

// min select the minimum value of a and b.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Read read the next len(p) bytes from the KDF context.
func (kdf *KDF) Read(p []byte) (n int, err error) {
	// Read the minimum of everything requested or whatever's left.
	toRead := min(len(p), kdf.length-kdf.position)
	// When there's no data left fail.
	if toRead == 0 {
		err = io.EOF
		return
	}
	// Use buffered data first to attempt to satisfy request.
	if len(kdf.buffer) > 0 {
		fromBuffer := min(len(kdf.buffer), toRead)
		copy(p, kdf.buffer[:fromBuffer])
		kdf.buffer = kdf.buffer[fromBuffer:]
		n = fromBuffer
	}
	// Calculate the number of full hash outputs required to satisfy request.
	iterations := ((toRead - n) + (kdf.digester.Size() - 1)) / kdf.digester.Size()
	for i := 0; i < iterations; i++ {
		osp := i2osp(kdf.iterations)
		kdf.iterations++
		if _, err = kdf.digester.Write(kdf.seed); err != nil {
			return
		}
		if _, err = kdf.digester.Write(osp); err != nil {
			return
		}
		if _, err = kdf.digester.Write(kdf.other); err != nil {
			return
		}
		t := kdf.digester.Sum(nil)
		tLen := len(t)
		// The last iteration may have some leftover data which we buffer for the next invocation of read.
		if tLen > toRead-n {
			tLen = toRead - n
			kdf.buffer = t[tLen:]
		}
		copy(p[n:], t[:tLen])
		n += tLen
		kdf.digester.Reset()
	}
	kdf.position = kdf.position + n
	return
}

func newKDF(seed, other []byte, hash crypto.Hash, offset uint32, length int) (kdf *KDF, err error) {
	if len(seed) == 0 {
		err = ErrInvalidSeedParameter
		return
	}
	// Calculate maximum size of the output based on the hash size.
	var maxlen = int64(1<<32) * int64(hash.Size())
	if length <= 0 || int64(length) > maxlen {
		err = ErrInvalidLengthParameter
		return
	}
	kdf = &KDF{
		seed:       seed,
		other:      other,
		length:     length,
		iterations: offset,
		position:   0,
		buffer:     nil,
		digester:   hash.New(),
	}
	return
}

// NewKDF1 create a new KDF1 context.
func NewKDF1(seed, other []byte, hash crypto.Hash, length int) (*KDF, error) {
	return newKDF(seed, other, hash, 0, length)
}

// NewKDF2 create a new KDF2 context.
func NewKDF2(seed, other []byte, hash crypto.Hash, length int) (*KDF, error) {
	return newKDF(seed, other, hash, 1, length)
}
