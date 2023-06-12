// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package argon2 implements the key derivation function Argon2.
// Argon2 was selected as the winner of the Password Hashing Competition and can
// be used to derive cryptographic keys from passwords.
//
// For a detailed specification of Argon2 see [1].
//
// If you aren't sure which function you need, use Argon2id (IDKey) and
// the parameter recommendations for your scenario.
//
// # Argon2i
//
// Argon2i (implemented by Key) is the side-channel resistant version of Argon2.
// It uses data-independent memory access, which is preferred for password
// hashing and password-based key derivation. Argon2i requires more passes over
// memory than Argon2id to protect from trade-off attacks. The first recommended
// parameters (taken from [2]) for non-interactive operations are time=1 and to
// use the maximum available memory.
//
// # Argon2id
//
// Argon2id (implemented by IDKey) is a hybrid version of Argon2 combining
// Argon2i and Argon2d. It uses data-independent memory access for the first
// half of the first iteration over the memory and data-dependent memory access
// for the rest. Argon2id is side-channel resistant and provides better brute-
// force cost savings due to time-memory tradeoffs than Argon2i. The first recommended
// parameters for non-interactive operations (taken from [2]) are time=1 and to
// use the maximum available memory.
//
// [1] https://github.com/P-H-C/phc-winner-argon2/blob/master/argon2-specs.pdf
// [2] https://datatracker.ietf.org/doc/html/rfc9106#section-4
// [3] https://datatracker.ietf.org/doc/html/rfc9106#section-3.1
package argon2

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"

	"golang.org/x/crypto/blake2b"
)

// Version is the Argon2 version implemented by this package.
const Version = 0x13

const (
	argon2d = iota
	argon2i
	argon2id
)

const (
	maxPasswordLength  = (1 << 32) - 1
	maxSecretLength    = (1 << 32) - 1
	minKeyLength       = 4
	defaultThreadCount = 4
	defaultSaltLength  = 16
	defaultKeyLength   = 128
	defaultMemory      = 65536
	defaultTime        = 3
)

// ErrMismatchedHashAndPassword is returned from CompareHashAndPassword when a password and hash do
// not match.
var ErrMismatchedHashAndPassword = errors.New("crypto/argon2: hashedPassword is not the hash of the given password")

// InvalidHashVersionError is returned from CompareHashAndPassword when a hash was created with
// an Argon2 algorithm other than the version specified by the RFC [3].
var InvalidHashVersionError = errors.New(fmt.Sprintf("crypto/argon2: only argon2 algorithm version '%d' is supported", Version))

// InvalidHashPrefixError is returned from CompareHashAndPassword when a hash starts with something other than '$'
type InvalidHashPrefixError byte

func (ih InvalidHashPrefixError) Error() string {
	return fmt.Sprintf("crypto/argon2: argon2 hashes must start with '$', but hashedSecret started with '%c'", byte(ih))
}

// ErrPasswordTooLong is returned when the password passed to GenerateFromPassword
// is longer than allowed by the RFC [3] (i.e. > 2^32-1 bytes).
type ErrPasswordTooLong int

func (ptl ErrPasswordTooLong) Error() string {
	return fmt.Sprintf("crypto/argon2: Argon2 passwords cannot exceed 2^(32)-1 bytes, but password is length %d", ptl)
}

// ErrSecretTooLong is returned when the secret passed to GenerateFromPassword
// is longer than allowed by the RFC [3] (i.e. > 2^32-1 bytes).
type ErrSecretTooLong int

func (stl ErrSecretTooLong) Error() string {
	return fmt.Sprintf("crypto/argon2: Argon2 secret values cannot exceed 2^(32)-1 bytes, but secret is length %d", stl)
}

// Key derives a key from the password, salt, and cost parameters using Argon2i
// returning a byte slice of length keyLen that can be used as cryptographic
// key. The CPU cost and parallelism degree must be greater than zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.Key([]byte("some password"), salt, 3, 32*1024, 4, 32)
//
// The RFC recommends[2] time=3, and memory=32*1024 is a sensible number.
// If using that amount of memory (32 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=32*1024 sets the memory cost to ~32 MB. The number of threads can be
// adjusted to the number of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func Key(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2i, password, salt, nil, nil, time, memory, threads, keyLen)
}

// IDKey derives a key from the password, salt, and cost parameters using
// Argon2id returning a byte slice of length keyLen that can be used as
// cryptographic key. The CPU cost and parallelism degree must be greater than
// zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.IDKey([]byte("some password"), salt, 3, 64*1024, 4, 32)
//
// The RFC suggests[2] that time=3 and memory=64*1024 are sensible numbers.
// If using that amount of memory (64 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
// adjusted to the numbers of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2id, password, salt, nil, nil, time, memory, threads, keyLen)
}

// IDKeyWithSecret derives a key from the password, salt, secret (also known as "pepper"),
// and cost parameters using Argon2id returning a byte slice of length keyLen that can be used as
// cryptographic key. The CPU cost and parallelism degree must be greater than
// zero.
//
// For example, you can get a derived key for e.g. AES-256 (which needs a
// 32-byte key) by doing:
//
//	key := argon2.IDKey([]byte("some password"), []byte("secret pepper"), salt, 3, 64*1024, 4, 32)
//
// The RFC suggests[2] that time=3 and memory=64*1024 are sensible numbers.
// If using that amount of memory (64 MB) is not possible in some contexts then
// the time parameter can be increased to compensate.
//
// The time parameter specifies the number of passes over the memory and the
// memory parameter specifies the size of the memory in KiB. For example
// memory=64*1024 sets the memory cost to ~64 MB. The number of threads can be
// adjusted to the numbers of available CPUs. The cost parameters should be
// increased as memory latency and CPU parallelism increases. Remember to get a
// good random salt.
func IDKeyWithSecret(password, salt, secret []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return deriveKey(argon2id, password, salt, secret, nil, time, memory, threads, keyLen)
}

// GenerateFromPassword returns the hash of the password using Argon2id with the given optional secret
// and parameters for `keyLength` (length of the generated key), `time` (number of iterations over memory),
// `memory` (in kibibytes), and `threads`. If 0 is passed for keyLength, time, memory, or
// threads, they will be replaced by default values keyLength=128, time=3, memory=65536, threads=4. A random salt
// of length 16 bytes will be generated.
//
// Example usage:
// myHashedPassword := argon2.GenerateFromPassword([]byte("mypassword"), []byte("optionalsecretpepper"), 3,  8*256, 2, 0)
//
// The authors provide more detail parameter recommendations for different system scenarios in the RFC [2].
//
// Use CompareHashAndPassword, as defined in this package,
// to compare the returned hashed password with its cleartext version.
// GenerateFromPassword does not accept passwords or secrets longer than 2^32-1 bytes, which
// are the longest passwords and secrets Argon2 will operate on.
func GenerateFromPassword(password, secret []byte, time, memory uint32, threads uint8, keyLength uint32) ([]byte, error) {
	if len(password) > maxPasswordLength {
		return nil, ErrPasswordTooLong(len(password))
	}
	if len(secret) > maxSecretLength {
		return nil, ErrSecretTooLong(len(secret))
	}
	p, err := newFromPassword(password, nil, secret, time, memory, threads, keyLength)
	if err != nil {
		return nil, err
	}
	return p.encode(), nil
}

// CompareHashAndPassword compares an Argon2 hashed password and an optional secret with a possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hashedPassword, plaintext, secret []byte) error {
	p, err := newFromHash(hashedPassword)
	if err != nil {
		return err
	}

	otherP, err := newFromPassword(plaintext, p.salt, secret, p.time, p.memory, p.threads, uint32(len(p.hash)))
	if subtle.ConstantTimeCompare(p.encode(), otherP.encode()) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

func newFromPassword(password, salt, secret []byte, time, memory uint32, threads uint8, keyLength uint32) (*hashed, error) {
	if threads == 0 {
		threads = defaultThreadCount
	}

	// Memory size m MUST be an integer number of kibibytes from 8*p to 2^(32)-1
	// as specified by the RFC [3].
	if memory == 0 {
		memory = defaultMemory
	}
	minMemory := 8 * uint32(threads)
	if memory < minMemory {
		memory = minMemory
	}
	if time < 1 {
		time = defaultTime
	}
	if keyLength < minKeyLength {
		keyLength = defaultKeyLength
	}

	p := new(hashed)
	p.time = time
	p.threads = threads
	p.memory = memory

	if salt == nil {
		salt = make([]byte, defaultSaltLength)
		_, err := io.ReadFull(rand.Reader, salt)
		if err != nil {
			return nil, err
		}
	}
	hash := IDKeyWithSecret(password, salt, secret, time, memory, threads, keyLength)
	p.hash = hash
	p.salt = salt
	return p, nil
}

func newFromHash(hashedSecret []byte) (*hashed, error) {
	p := new(hashed)
	_, err := p.decode(hashedSecret)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func deriveKey(mode int, password, salt, secret, data []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	if time < 1 {
		panic("argon2: number of rounds too small")
	}
	if threads < 1 {
		panic("argon2: parallelism degree too low")
	}
	h0 := initHash(password, salt, secret, data, time, memory, uint32(threads), keyLen, mode)

	memory = memory / (syncPoints * uint32(threads)) * (syncPoints * uint32(threads))
	if memory < 2*syncPoints*uint32(threads) {
		memory = 2 * syncPoints * uint32(threads)
	}
	B := initBlocks(&h0, memory, uint32(threads))
	processBlocks(B, time, memory, uint32(threads), mode)
	return extractKey(B, memory, uint32(threads), keyLen)
}

type hashed struct {
	hash         []byte
	salt         []byte
	time, memory uint32
	threads      uint8
}

func (p *hashed) encode() []byte {
	b := bytes.Buffer{}

	b.WriteString("$argon2id$v=19$m=")
	b.WriteString(strconv.FormatUint(uint64(p.memory), 10))

	b.WriteString(",t=")
	b.WriteString(strconv.FormatUint(uint64(p.time), 10))

	b.WriteString(",p=")
	b.WriteString(strconv.FormatUint(uint64(p.threads), 10))

	b.WriteString("$")
	b.WriteString(base64.RawStdEncoding.EncodeToString(p.salt))

	b.WriteString("$")
	b.WriteString(base64.RawStdEncoding.EncodeToString(p.hash))

	return b.Bytes()
}

func (p *hashed) decode(sbytes []byte) (int, error) {
	if sbytes[0] != '$' {
		return -1, InvalidHashPrefixError(sbytes[0])
	}

	subSlices := bytes.Split(sbytes, []byte("$"))
	if len(subSlices) != 6 {
		return -1, errors.New(fmt.Sprintf("crypto/argon2: %s is an invalid argument", sbytes))
	}

	if !bytes.Equal(subSlices[2], []byte("v=19")) {
		return -1, InvalidHashVersionError
	}

	decodedSalt, err := base64.RawStdEncoding.DecodeString(string(subSlices[4]))
	if err != nil {
		return -1, err
	}
	p.salt = decodedSalt

	decodedHash, err := base64.RawStdEncoding.DecodeString(string(subSlices[5]))
	if err != nil {
		return -1, err
	}
	p.hash = decodedHash

	_, err = fmt.Sscanf(string(subSlices[3]), "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads)
	if err != nil {
		return -1, err
	}

	return 0, nil
}

func (p *hashed) String() string {
	return fmt.Sprintf("&{hash: %#v, salt: %#v, memory: %d, time: %c, threads: %c}", string(p.hash), p.salt, p.memory, p.time, p.threads)
}

const (
	blockLength = 128
	syncPoints  = 4
)

type block [blockLength]uint64

func initHash(password, salt, key, data []byte, time, memory, threads, keyLen uint32, mode int) [blake2b.Size + 8]byte {
	var (
		h0     [blake2b.Size + 8]byte
		params [24]byte
		tmp    [4]byte
	)

	b2, _ := blake2b.New512(nil)
	binary.LittleEndian.PutUint32(params[0:4], threads)
	binary.LittleEndian.PutUint32(params[4:8], keyLen)
	binary.LittleEndian.PutUint32(params[8:12], memory)
	binary.LittleEndian.PutUint32(params[12:16], time)
	binary.LittleEndian.PutUint32(params[16:20], uint32(Version))
	binary.LittleEndian.PutUint32(params[20:24], uint32(mode))
	b2.Write(params[:])
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(password)))
	b2.Write(tmp[:])
	b2.Write(password)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(salt)))
	b2.Write(tmp[:])
	b2.Write(salt)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(key)))
	b2.Write(tmp[:])
	b2.Write(key)
	binary.LittleEndian.PutUint32(tmp[:], uint32(len(data)))
	b2.Write(tmp[:])
	b2.Write(data)
	b2.Sum(h0[:0])
	return h0
}

func initBlocks(h0 *[blake2b.Size + 8]byte, memory, threads uint32) []block {
	var block0 [1024]byte
	B := make([]block, memory)
	for lane := uint32(0); lane < threads; lane++ {
		j := lane * (memory / threads)
		binary.LittleEndian.PutUint32(h0[blake2b.Size+4:], lane)

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 0)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+0] {
			B[j+0][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}

		binary.LittleEndian.PutUint32(h0[blake2b.Size:], 1)
		blake2bHash(block0[:], h0[:])
		for i := range B[j+1] {
			B[j+1][i] = binary.LittleEndian.Uint64(block0[i*8:])
		}
	}
	return B
}

func processBlocks(B []block, time, memory, threads uint32, mode int) {
	lanes := memory / threads
	segments := lanes / syncPoints

	processSegment := func(n, slice, lane uint32, wg *sync.WaitGroup) {
		var addresses, in, zero block
		if mode == argon2i || (mode == argon2id && n == 0 && slice < syncPoints/2) {
			in[0] = uint64(n)
			in[1] = uint64(lane)
			in[2] = uint64(slice)
			in[3] = uint64(memory)
			in[4] = uint64(time)
			in[5] = uint64(mode)
		}

		index := uint32(0)
		if n == 0 && slice == 0 {
			index = 2 // we have already generated the first two blocks
			if mode == argon2i || mode == argon2id {
				in[6]++
				processBlock(&addresses, &in, &zero)
				processBlock(&addresses, &addresses, &zero)
			}
		}

		offset := lane*lanes + slice*segments + index
		var random uint64
		for index < segments {
			prev := offset - 1
			if index == 0 && slice == 0 {
				prev += lanes // last block in lane
			}
			if mode == argon2i || (mode == argon2id && n == 0 && slice < syncPoints/2) {
				if index%blockLength == 0 {
					in[6]++
					processBlock(&addresses, &in, &zero)
					processBlock(&addresses, &addresses, &zero)
				}
				random = addresses[index%blockLength]
			} else {
				random = B[prev][0]
			}
			newOffset := indexAlpha(random, lanes, segments, threads, n, slice, lane, index)
			processBlockXOR(&B[offset], &B[prev], &B[newOffset])
			index, offset = index+1, offset+1
		}
		wg.Done()
	}

	for n := uint32(0); n < time; n++ {
		for slice := uint32(0); slice < syncPoints; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < threads; lane++ {
				wg.Add(1)
				go processSegment(n, slice, lane, &wg)
			}
			wg.Wait()
		}
	}

}

func extractKey(B []block, memory, threads, keyLen uint32) []byte {
	lanes := memory / threads
	for lane := uint32(0); lane < threads-1; lane++ {
		for i, v := range B[(lane*lanes)+lanes-1] {
			B[memory-1][i] ^= v
		}
	}

	var block [1024]byte
	for i, v := range B[memory-1] {
		binary.LittleEndian.PutUint64(block[i*8:], v)
	}
	key := make([]byte, keyLen)
	blake2bHash(key, block[:])
	return key
}

func indexAlpha(rand uint64, lanes, segments, threads, n, slice, lane, index uint32) uint32 {
	refLane := uint32(rand>>32) % threads
	if n == 0 && slice == 0 {
		refLane = lane
	}
	m, s := 3*segments, ((slice+1)%syncPoints)*segments
	if lane == refLane {
		m += index
	}
	if n == 0 {
		m, s = slice*segments, 0
		if slice == 0 || lane == refLane {
			m += index
		}
	}
	if index == 0 || lane == refLane {
		m--
	}
	return phi(rand, uint64(m), uint64(s), refLane, lanes)
}

func phi(rand, m, s uint64, lane, lanes uint32) uint32 {
	p := rand & 0xFFFFFFFF
	p = (p * p) >> 32
	p = (p * m) >> 32
	return lane*lanes + uint32((s+m-(p+1))%uint64(lanes))
}
