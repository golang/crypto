// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package md5crypt implements Apache-specific MD5 apr1 password hashing
// algorithm. Details and reference implementation are available at
// https://httpd.apache.org/docs/2.4/en/misc/password_encryptions.html
package md5crypt // import "golang.org/x/crypto/crypt/md5crypt"

import (
	"crypto/md5"
	"crypto/subtle"
	"errors"
)

var (
	// APR1Magic salt prefix is used by the Apache for MD5 encryption.
	APR1Magic = []byte("$apr1$")
	// MD5Magic salt prefix is used by various Linux/BSD crypt implementations.
	MD5Magic = []byte("$1$")

	// ErrUnsupportedSalt is returned when provided salt or hashed password
	// doesn't have APR1Magic or MD5Magic prefix.
	ErrUnsupportedSalt = errors.New("crypto/crypt/md5crypt: unsupported salt, must have $apr1$ or $1$ prefix")

	// ErrMismatchedHashAndPassword is returned from CompareHashAndPassword when
	// a password and hash do not match.
	ErrMismatchedHashAndPassword = errors.New("crypto/crypt/md5crypt: hashedPassword is not the hash of the given password")
)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var md5CryptSwaps = [16]int{12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11}

// GenerateFromPassword returns the MD5 APR1 hash of the password. Salt must
// start with either APR1Magic or MD5Magic prefix, followed by up to 8 bytes of
// salt prefix and optionally terminate with a '$'. Any remaining salt bytes
// will be ignored.
func GenerateFromPassword(password, salt []byte) ([]byte, error) {
	magic, trueSalt, err := decodeSalt(salt)
	if err != nil {
		return nil, err
	}

	d := md5.New()
	d.Write(password)
	d.Write(magic)
	d.Write(trueSalt)

	d2 := md5.New()
	d2.Write(password)
	d2.Write(trueSalt)
	d2.Write(password)

	for i, mixin := 0, d2.Sum(nil); i < len(password); i++ {
		d.Write([]byte{mixin[i%16]})
	}

	for i := len(password); i != 0; i >>= 1 {
		if i&1 == 0 {
			d.Write([]byte{password[0]})
		} else {
			d.Write([]byte{0})
		}
	}

	final := d.Sum(nil)

	for i := 0; i < 1000; i++ {
		d2 := md5.New()
		if i&1 == 0 {
			d2.Write(final)
		} else {
			d2.Write(password)
		}

		if i%3 != 0 {
			d2.Write(trueSalt)
		}

		if i%7 != 0 {
			d2.Write(password)
		}

		if i&1 == 0 {
			d2.Write(password)
		} else {
			d2.Write(final)
		}
		final = d2.Sum(nil)
	}

	saltPrefixLength := len(magic) + len(trueSalt)
	result := make([]byte, saltPrefixLength, saltPrefixLength+23)
	copy(result, salt)
	result = append(result, '$')
	var v, bits uint
	for _, i := range md5CryptSwaps {
		v |= (uint(final[i]) << bits)
		for bits = bits + 8; bits > 6; bits -= 6 {
			result = append(result, itoa64[v&0x3f])
			v >>= 6
		}
	}
	result = append(result, itoa64[v&0x3f])
	return result, nil
}

// CompareHashAndPassword compares a hashed password with its possible plaintext
// equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	hashed, err := GenerateFromPassword(password, hashedPassword)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(hashed, hashedPassword) == 1 {
		return nil
	}
	return ErrMismatchedHashAndPassword
}

// decodeSalt splits the salt into magic and "true" salt. Returned values are
// subslices of the input slice.
func decodeSalt(salt []byte) (magic []byte, trueSalt []byte, err error) {
	maybeAPR1 := salt[:len(APR1Magic)]
	maybeMD5 := salt[:len(MD5Magic)]
	a := subtle.ConstantTimeCompare(maybeAPR1, APR1Magic)
	b := subtle.ConstantTimeCompare(maybeMD5, MD5Magic)
	if a+b == 0 {
		return nil, nil, ErrUnsupportedSalt
	}
	if a == 1 {
		magic = maybeAPR1
		salt = salt[len(APR1Magic):]
	} else {
		magic = maybeMD5
		salt = salt[len(MD5Magic):]
	}

	if len(salt) == 0 {
		return magic, salt, nil
	}
	slen := len(salt)
	if slen > 8 {
		slen = 8
	}
	for i := 0; i < slen; i++ {
		if salt[i] == '$' {
			return magic, salt[:i], nil
		}
	}
	return magic, salt[:slen], nil
}
