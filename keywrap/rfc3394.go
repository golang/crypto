package minerva

import (
	"crypto/aes"
	"errors"
)

var defaultIV = []byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

func aES(key, in []byte) ([]byte, error) {
	k, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	out := make([]byte, k.BlockSize())
	k.Encrypt(out, in)
	return out, nil
}

func aES1(key, in []byte) ([]byte, error) {
	k, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	out := make([]byte, k.BlockSize())
	k.Decrypt(out, in)
	return out, nil
}

// UnWrapKey - Unwrap key using KEK as par rfc 3394
func UnWrapKey(KEK, CipherText []byte) ([]byte, error) {

	if len(CipherText)%8 != 0 {
		return nil, errors.New("invalid data length")
	}
	if len(CipherText) < 16 {
		return nil, errors.New("invalid data length")
	}

	A := CipherText[0:8]
	n := len(CipherText)/8 - 1
	R := make([][8]byte, n+1)
	for i := 1; i <= n; i++ {
		copy(R[i][:], CipherText[8*(i):8*(i+1)])
	}
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := (n * j) + i

			A[7] ^= uint8(t & 0xff)
			if t > 0xff {
				A[6] ^= byte((t >> 8) & 0xff)
				A[5] ^= byte((t >> 16) & 0xff)
				A[4] ^= byte((t >> 24) & 0xff)
			}

			B, e := aES1(KEK, append(A, R[i][:]...))
			if e != nil {
				return nil, e
			}
			A = B[0:8]
			copy(R[i][:], B[8:16])
		}
	}
	tmp := A[:]
	for i := 1; i <= n; i++ {
		tmp = append(tmp, R[i][:]...)
	}
	return tmp, nil

}

// WrapKey - Wrap key using KEK as par rfc 3394
func WrapKey(KEK, KEYData, IV []byte) ([]byte, error) {

	if len(KEYData)%8 != 0 {
		return nil, errors.New("invalid data length")
	}

	if IV == nil {
		IV = defaultIV
	}
	key := KEK
	n := len(KEYData) / 8
	R := make([][8]byte, n+1)
	for i := 1; i <= n; i++ {
		copy(R[i][:], KEYData[8*(i-1):8*(i)])
	}
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			B, e := aES(key, append(IV[:], R[i][:]...))
			if e != nil {
				return nil, e
			}
			t := (n * j) + i
			IV = B[0:8]
			IV[7] = IV[7] ^ byte(t&0xff)

			if t > 0xff {
				IV[6] ^= byte((t >> 8) & 0xff)
				IV[5] ^= byte((t >> 16) & 0xff)
				IV[4] ^= byte((t >> 24) & 0xff)
			}
			copy(R[i][:], B[8:16])
		}
	}
	tmp := IV
	for i := 1; i <= n; i++ {
		tmp = append(tmp, R[i][:]...)
	}
	return tmp, nil
}

// WrapKeyPadded - Wrap key using KEK as par rfc 5649
func WrapKeyPadded(KEK, KEYData []byte) ([]byte, error) {
	n := len(KEYData)
	if len(KEYData)%8 != 0 {
		pad := make([]byte, 8-(len(KEYData)%8))
		KEYData = append(KEYData, pad...)
	}
	IV := []byte{0xA6, 0x59, 0x59, 0xA6, 0x00, 0x00, 0x00, 0x00}
	//support 16 bit key size
	IV[7] |= byte(n & 0xff)
	IV[6] |= byte((n >> 8) & 0xff)
	IV[5] |= byte((n >> 16) & 0xff)
	IV[4] |= byte((n >> 24) & 0xff)

	if len(KEYData) == 8 {
		return aES(KEK, append(IV, KEYData...))
	}
	return WrapKey(KEK, KEYData, IV)
}

//UnwrapPadded - Unwrap key using KEK as par rfc 5649
func UnwrapPadded(KEK, CipherText []byte) ([]byte, error) {
	var out []byte
	var e error
	n := len(CipherText)
	if n == 16 {
		out, e = aES1(KEK, CipherText)
		if e != nil {
			return nil, e
		}
	} else {
		out, e = UnWrapKey(KEK, CipherText)
		if e != nil {
			return nil, e
		}
	}
	A := out[0:8]
	mli := int(A[7]) | (int(A[6]) << 8 & 0x0000ff00)
	b := out[8:n]
	return b[0:mli], nil
}
