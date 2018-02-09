/*Package rc6 ...
RC6 (Rivest cipher 6) is a symmetric key block cipher derived from RC5. It was designed by Ron Rivest, Matt Robshaw, Ray Sidney, and Yiqun Lisa Yin to meet the requirements of the Advanced Encryption Standard (AES) competition. The algorithm was one of the five finalists, and also was submitted to the NESSIE and CRYPTREC projects.

RC6 proper has a block size of 128 bits and supports key sizes of 128, 192, and 256 bits up to 2040-bits, but, like RC5, it may be parameterised to support a wide variety of word-lengths, key sizes, and number of rounds. However, this implementation uses 32 bit words and a fixed block size of 16 bytes.

Abstract paraphrased from Wikipedia: https://en.wikipedia.org/wiki/RC6

This implementation is ©2017 by Jon Jenkins <jon@mj12.su>. Released under MIT license.
*/
package rc6

import (
	"encoding/binary"
)

const blockSize = 16

var defaultRounds uint32 = 20

var constP uint32 = 0xB7E15163
var constQ uint32 = 0x9E3779B9

//Cipher is a struct containing an RC6 key schedule
type Cipher struct {
	rounds   uint32
	keyLen   uint8
	key      []uint32
	keySched []uint32
}

//NewCipher returns a Cipher struct containing an RC6 key schedule, ready to use
//as a block cipher. Key length is parametric and determined by the length in bytes of
//the key. Commonly used key lengths are 16,24, and 32 bytes/
func NewCipher(key []byte) Cipher {
	var c Cipher
	for len(key)%4 != 0 {
		key = append(key, 0)
	}
	c.rounds = defaultRounds
	c.key = make([]uint32, len(key)/4)
	var a, b, j, i, s, v, klen, keySchedMax uint32
	klen = uint32(len(key))
	for i = 0; i < klen; i += 4 {
		c.key[i/4] = binary.LittleEndian.Uint32(key[i:])
	}
	keySchedMax = 2*c.rounds + 4
	c.keyLen = uint8(len(c.key))
	c.keySched = make([]uint32, keySchedMax)
	c.keySched[0] = constP
	for i = 1; i < keySchedMax; i++ {
		c.keySched[i] = c.keySched[i-1] + constQ
	}
	v = 3 * (2*c.rounds + 4)
	if uint32(c.keyLen) > (2*c.rounds + 4) {
		v = uint32(c.keyLen)
	}
	a = 0
	b = 0
	i = 0
	j = 0
	for s = 1; s <= v; s++ {
		c.keySched[i] = rotl32(c.keySched[i]+a+b, 3)
		a = c.keySched[i]
		c.key[j] = rotl32(c.key[j]+a+b, a+b)
		b = c.key[j]
		i = (i + 1) % (2*c.rounds + 4)
		j = (j + 1) % uint32(c.keyLen)
	}
	return c
}

//BlockSize returns the block size of RC6, which in our case is always 16
func (Cipher) BlockSize() int {
	return int(blockSize)
}

//Encrypt encrypts one block of data
func (this Cipher) Encrypt(dst, src []byte) {
	if len(src) != blockSize {
		panic("Incorrect amount of data passed to Encrypt")
	}
	ct := make([]uint32, 4)
	for i := 0; i < blockSize; i += 4 {
		ct[i/4] = binary.LittleEndian.Uint32(src[i:])
	}
	var a, b, c, d, t, u, i, x uint32
	a = ct[0]
	b = ct[1]
	c = ct[2]
	d = ct[3]
	b = b + this.keySched[0]
	d = d + this.keySched[1]
	for i = 1; i <= this.rounds; i++ {

		t = rotl32((b * (2*b + 1)), 5)
		u = rotl32((d * (2*d + 1)), 5)
		a = rotl32((a^t), u) + this.keySched[2*i]
		c = rotl32((c^u), t) + this.keySched[2*i+1]
		x = a
		a = b
		b = c
		c = d
		d = x
	}
	a = a + this.keySched[2*this.rounds+2]
	c = c + this.keySched[2*this.rounds+3]
	binary.LittleEndian.PutUint32(dst[0:], a)
	binary.LittleEndian.PutUint32(dst[4:], b)
	binary.LittleEndian.PutUint32(dst[8:], c)
	binary.LittleEndian.PutUint32(dst[12:], d)

}

//Decrypt decrypts one block of data
func (this Cipher) Decrypt(dst, src []byte) {
	if len(src) != blockSize {
		panic("Incorrect amount of data passed to Encrypt")
	}
	ct := make([]uint32, 4)
	for i := 0; i < blockSize; i += 4 {
		ct[i/4] = binary.LittleEndian.Uint32(src[i:])
	}
	var a, b, c, d, t, u, i, x uint32
	a = ct[0]
	b = ct[1]
	c = ct[2]
	d = ct[3]
	c = c - this.keySched[2*this.rounds+3]
	a = a - this.keySched[2*this.rounds+2]
	for i = this.rounds; i >= 1; i-- {
		x = d
		d = c
		c = b
		b = a
		a = x
		u = rotl32((d * (2*d + 1)), 5)
		t = rotl32((b * (2*b + 1)), 5)
		c = rotr32(c-this.keySched[2*i+1], t) ^ u
		a = rotr32(a-this.keySched[2*i], u) ^ t
	}
	d = d - this.keySched[1]
	b = b - this.keySched[0]
	binary.LittleEndian.PutUint32(dst[0:], a)
	binary.LittleEndian.PutUint32(dst[4:], b)
	binary.LittleEndian.PutUint32(dst[8:], c)
	binary.LittleEndian.PutUint32(dst[12:], d)

}

func rotl32(x, y uint32) uint32 {
	var w uint32 = 32
	return (((x) << (y & (w - 1))) | ((x) >> (w - (y & (w - 1)))))
}

func rotr32(x, y uint32) uint32 {
	var w uint32 = 32
	return (((x) >> (y & (w - 1))) | ((x) << (w - (y & (w - 1)))))
}
