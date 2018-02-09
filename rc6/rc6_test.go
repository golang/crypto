package rc6

import (
	"bytes"
	"encoding/hex"
	"testing"
)

var key128 = make([]byte, 16)
var key192 = make([]byte, 24)
var key256 = make([]byte, 32)

var decVector128, decVector192, decVector256 []byte

func TestNewCipher(t *testing.T) {

}

func TestEncrypt(t *testing.T) {
	c := NewCipher(key128)
	// Implicit all zeros
	t.Log("Testing 128 bit enc")
	pt, _ := hex.DecodeString("00000000000000000000000000000000")
	want, _ := hex.DecodeString("8fc3a53656b1f778c129df4e9848a41e")
	ct := make([]byte, c.BlockSize())
	c.Encrypt(ct, pt)
	if bytes.Compare(ct, want) != 0 {
		t.Error("Does not have wanted ciphertext!")
	}
	decVector128 = want
	testKey1, _ := hex.DecodeString("0123456789abcdef0112233445566778")
	c = NewCipher(testKey1)
	pt, _ = hex.DecodeString("02132435465768798a9bacbdcedfe0f1")
	want, _ = hex.DecodeString("524e192f4715c6231f51f6367ea43f18")
	c.Encrypt(ct, pt)
	if bytes.Compare(ct, want) != 0 {
		t.Error("Does not have wanted ciphertext!")
	}
	t.Log("Testing 192 bit enc")
	//Implicit all zeros again
	testKey2 := make([]byte, 24)
	c = NewCipher(testKey2)
	pt = make([]byte, c.BlockSize())
	ct = make([]byte, c.BlockSize())
	c.Encrypt(ct, pt)
	want, _ = hex.DecodeString("6cd61bcb190b30384e8a3f168690ae82")
	if bytes.Compare(ct, want) != 0 {
		t.Error("Does not have wanted ciphertext!")
	}
	decVector192 = want
	t.Log("Testing 256 bit enc")
	//Implicit all zeros again
	testKey3 := make([]byte, 32)
	c = NewCipher(testKey3)
	pt = make([]byte, c.BlockSize())
	ct = make([]byte, c.BlockSize())
	c.Encrypt(ct, pt)
	want, _ = hex.DecodeString("8f5fbd0510d15fa893fa3fda6e857ec2")
	if bytes.Compare(ct, want) != 0 {
		t.Error("Does not have wanted ciphertext!")
	}
	decVector256 = want
}

func TestDecrypt(t *testing.T) {
	//We want all zeros in this series of decryption tests
	t.Log("Testing 128 bit dec")
	c := NewCipher(make([]byte, 16))
	want := make([]byte, c.BlockSize())
	pt := make([]byte, c.BlockSize())
	c.Decrypt(pt, decVector128)
	if bytes.Compare(pt, want) != 0 {
		t.Error("Does not have wanted plaintext!")
	}
	c = NewCipher(make([]byte, 24))
	c.Decrypt(pt, decVector192)
	if bytes.Compare(pt, want) != 0 {
		t.Error("Does not have wanted plaintext!")
	}
	c = NewCipher(make([]byte, 32))
	c.Decrypt(pt, decVector256)
	if bytes.Compare(pt, want) != 0 {
		t.Error("Does not have wanted plaintext!")
	}
}

func TestBlockSize(t *testing.T) {
	c := NewCipher(key128)
	if c.BlockSize() != 16 {
		t.Fail()
	}
}
