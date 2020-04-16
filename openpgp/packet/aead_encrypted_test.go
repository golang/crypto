// Copyright (C) 2018 ProtonTech AG

package packet

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	mathrand "math/rand"
	"testing"
)

// Note: This implementation does not produce packets with chunk sizes over
// 1<<27, but can parse packets with chunk size octets up to 56 and decrypt
// them within limits of the running system. See RFC4880bis, sec 5.16.
var maxChunkSizeExp = 62

const (
	keyLength          = 16
	maxPlaintextLength = 1 << 18
)

func TestAeadRFCParse(t *testing.T) {
	for _, sample := range samplesAeadEncryptedDataPacket {
		key, _ := hex.DecodeString(sample.cek)
		packetBytes, _ := hex.DecodeString(sample.full)
		packetReader := bytes.NewBuffer(packetBytes)
		packet := new(AEADEncrypted)
		ptype, _, contentsReader, err := readHeader(packetReader)
		if ptype != packetTypeAEADEncrypted || err != nil {
			t.Error("Error reading packet header")
		}
		if err = packet.parse(contentsReader); err != nil {
			t.Error(err)
		}
		// decrypted plaintext can be read from 'rc'
		rc, err := packet.decrypt(key)
		if err != nil {
			t.Error(err)
		}
		got, err := readDecryptedStream(rc)
		if err != nil {
			t.Error(err)
		}

		want, _ := hex.DecodeString(sample.plaintext)
		if !bytes.Equal(got, want) {
			t.Errorf("Error opening:\ngot\n%s\nwant\n%s", got, want)
		}
	}
}

// Test if it is possible to stream an empty plaintext correctly. For
// compatibility with OpenPGPjs, if the stream has no contents, it has two
// authentication tags: One for the empty chunk, and the final auth. tag. This
// test also checks if it cannot decrypt a corrupt stream of empty plaintext.
func TestAeadEmptyStream(t *testing.T) {
	key := randomKey(16)
	config := randomConfig()
	raw, _, err := randomStream(key, 0, config)
	if err != nil {
		t.Error(err)
	}
	// Packet is ready.
	corruptBytes := make([]byte, len(raw.Bytes()))
	copy(corruptBytes, raw.Bytes())
	for bytes.Equal(corruptBytes, raw.Bytes()) {
		corruptBytes[mathrand.Intn(len(corruptBytes)-5)+5] = byte(mathrand.Intn(256))
	}
	corrupt := bytes.NewBuffer(corruptBytes)

	// Decrypt correct stream
	packet := new(AEADEncrypted)
	ptype, _, contentsReader, err := readHeader(raw)
	if ptype != packetTypeAEADEncrypted || err != nil {
		t.Error("Error reading packet header")
	}
	if err = packet.parse(contentsReader); err != nil {
		t.Error(err)
	}
	// decrypted plaintext can be read from 'rc'
	rc, err := packet.decrypt(key)

	_, err = readDecryptedStream(rc)
	if err != nil {
		t.Error(err)
	}

	// Decrypt corrupt stream
	packet = new(AEADEncrypted)
	ptype, _, contentsReader, err = readHeader(corrupt)
	if ptype != packetTypeAEADEncrypted || err != nil {
		t.Error("Error reading packet header")
	}
	if err = packet.parse(contentsReader); err != nil {
		t.Error(err)
	}
	// decrypted plaintext can be read from 'rc'
	rc, err = packet.decrypt(key)

	_, err = readDecryptedStream(rc)
	if err == nil {
		t.Errorf("No error raised when reading corrupt stream with empty plaintext")
	}
}

// Tests if encrypt/decrypt functions are callable and correct with a nil config
func TestAeadNilConfigStream(t *testing.T) {
	// Sample key
	key := randomKey(16)
	randomLength := mathrand.Intn(maxPlaintextLength) + 1
	raw, plain, err := randomStream(key, randomLength, nil)
	if err != nil {
		t.Error(err)
	}
	// Packet is ready in 'raw'

	packet := new(AEADEncrypted)

	ptype, _, contentsReader, err := readHeader(raw)
	if ptype != packetTypeAEADEncrypted || err != nil {
		t.Error("Error reading packet header")
	}

	if err = packet.parse(contentsReader); err != nil {
		t.Error(err)
	}
	// decrypted plaintext can be read from 'rc'
	rc, err := packet.decrypt(key)

	got, err := readDecryptedStream(rc)
	if err != nil {
		t.Error(err)
	}

	want := plain
	if !bytes.Equal(got, want) {
		t.Errorf("Error encrypting/decrypting random stream with nil config")
	}
}

// Encrypts and decrypts a random stream, checking correctness and integrity
func TestAeadStreamRandomizeSlow(t *testing.T) {
	key := randomKey(16)
	config := randomConfig()
	randomLength := mathrand.Intn(maxPlaintextLength) + 1
	raw, plain, err := randomStream(key, randomLength, config)
	if err != nil {
		t.Error(err)
	}
	// Packet is ready in 'raw'

	packet := new(AEADEncrypted)
	ptype, _, contentsReader, err := readHeader(raw)
	if ptype != packetTypeAEADEncrypted || err != nil {
		t.Error("Error reading packet header")
	}

	if err = packet.parse(contentsReader); err != nil {
		t.Error(err)
	}
	// decrypted plaintext can be read from 'rc'
	rc, err := packet.decrypt(key)

	got, err := readDecryptedStream(rc)
	if err != nil {
		t.Error(err)
	}
	// Close MUST be called - it checks if the final chunk was witnessed
	if err = rc.Close(); err != nil {
		t.Error(err)
	}
	want := plain
	if !bytes.Equal(got, want) {
		t.Errorf("Error encrypting/decrypting random stream")
	}
}

// Encrypts a random stream, corrupt some bytes, and check if it fails
func TestAeadCorruptStreamRandomizeSlow(t *testing.T) {
	key := randomKey(16)
	config := randomConfig()
	randomLength := mathrand.Intn(maxPlaintextLength) + 1
	raw, plain, err := randomStream(key, randomLength, config)
	if err != nil {
		t.Error(err)
	}

	// Corrupt some bytes of the stream
	for j := 0; j < 10; j++ {
		index := mathrand.Intn(len(raw.Bytes()))
		if index < 8 || len(plain) == 0 {
			// avoid corrupting header or nonce, that's useless
			continue
		}
		raw.Bytes()[index] = 255 - raw.Bytes()[index]
	}
	packet := new(AEADEncrypted)
	ptype, _, contentsReader, err := readHeader(raw)
	if ptype != packetTypeAEADEncrypted || err != nil {
		t.Error("Error reading packet header")
	}

	if err = packet.parse(contentsReader); err != nil {
		// Header was corrupted
		return
	}
	rc, err := packet.decrypt(key)
	got, err := readDecryptedStream(rc)
	if err == nil || err == io.EOF {
		t.Errorf("No error raised when decrypting corrupt stream")
	}
	if bytes.Equal(got, plain) {
		t.Errorf("Error: Succesfully decrypted corrupt stream")
	}
}

// Encrypts a random stream, truncate the end, and check if it fails
func TestAeadTruncatedStreamRandomizeSlow(t *testing.T) {
	key := randomKey(16)
	config := randomConfig()
	randomLength := mathrand.Intn(maxPlaintextLength)
	if randomLength < 16 {
		return
	}

	raw, plain, err := randomStream(key, randomLength, config)
	if err != nil {
		t.Error(err)
	}

	// Truncate the packet by some bytes
	var truncatedRaw []byte
	cut := 0
	for cut == 0 {
		cut = mathrand.Intn(randomLength / 2)
	}
	truncatedRaw = raw.Bytes()[:len(raw.Bytes())-cut]
	truncated := bytes.NewBuffer(truncatedRaw)

	packet := new(AEADEncrypted)
	ptype, _, truncatedContentsReader, err := readHeader(truncated)
	if ptype != packetTypeAEADEncrypted || err != nil {
		t.Error("Error reading packet header")
	}

	if err = packet.parse(truncatedContentsReader); err != nil {
		t.Error(err)
	}
	rc, err := packet.decrypt(key)
	if err != nil {
		return
	}
	got, err := readDecryptedStream(rc)
	if err == nil || err == io.EOF {
		t.Errorf("No truncate error raised when decrypting truncated stream")
	}
	if bytes.Equal(got, plain) {
		t.Errorf("Error: Succesfully decrypted truncated stream")
	}
}

// Encrypts a random stream, truncate the end, and check if it fails
func TestAeadUnclosedStreamRandomizeSlow(t *testing.T) {
	key := randomKey(16)
	config := randomConfig()
	ptLen := mathrand.Intn(maxPlaintextLength)
	// Sample random plaintext of given length
	plain := make([]byte, ptLen)
	_, err := rand.Read(plain)
	if err != nil {
		t.Error(err)
	}
	// 'writeCloser' encrypts and writes the plaintext bytes.
	rawCipher := bytes.NewBuffer(nil)
	writeCloser, err := SerializeAEADEncrypted(
		rawCipher, key, config.Cipher(), config.AEAD().Mode(), config,
	)
	if err != nil {
		t.Error(err)
	}
	// Write the partial lengths packet into 'raw'
	if _, err = writeCloser.Write(plain); err != nil {
		t.Error(err)
	}
	// Don't call Close

	packet := new(AEADEncrypted)
	_, _, contentsReader, err := readHeader(rawCipher)
	if err != nil {
		return
	}

	if err = packet.parse(contentsReader); err != nil {
		return
	}
	rc, err := packet.decrypt(key)
	if err != nil {
		return
	}
	got, err := readDecryptedStream(rc)
	if err == nil || err == io.EOF {
		t.Errorf("No error raised when decrypting unclosed stream")
	}
	if bytes.Equal(got, plain) {
		t.Errorf("Error: Succesfully decrypted unclosed stream")
	}
}

// ----------------------------------- //
// -------       UTILS       --------- //
// ----------------------------------- //

func randomKey(length int) []byte {
	key := make([]byte, length)
	_, err := rand.Read(key)
	if err != nil {
		panic("can't read from rand")
	}
	return key
}

func randomConfig() *Config {
	var aeadCompatibleCiphers = []CipherFunction{
		CipherAES128,
		CipherAES192,
		CipherAES256,
	}
	var modes = []AEADMode{
		AEADModeEAX,
		AEADModeOCB,
		AEADModeExperimentalGCM,
	}

	// Random chunk size
	chunkSizeExp := 6 + mathrand.Intn(maxChunkSizeExp-5)
	chunkSize := uint64(1 << uint(chunkSizeExp))
	// Random cipher and mode
	ciph := aeadCompatibleCiphers[mathrand.Intn(len(aeadCompatibleCiphers))]
	aeadConf := AEADConfig{
		ChunkSize:   uint64(chunkSize),
		DefaultMode: modes[mathrand.Intn(len(modes))],
	}
	config := &Config{
		AEADConfig:    &aeadConf,
		DefaultCipher: ciph,
	}
	return config
}

// Samples a random plaintext and gives the raw AEADEncrypted packet contents.
// Returns said contents, the plaintext, and an error.
func randomStream(key []byte, ptLen int, config *Config) (*bytes.Buffer, []byte, error) {
	// Sample random plaintext of given length
	plaintext := make([]byte, ptLen)
	_, err := rand.Read(plaintext)
	if err != nil {
		return nil, nil, err
	}

	// 'writeCloser' encrypts and writes the plaintext bytes.
	rawCipher := bytes.NewBuffer(nil)
	writeCloser, err := SerializeAEADEncrypted(
		rawCipher, key, config.Cipher(), config.AEAD().Mode(), config,
	)
	if err != nil {
		return nil, nil, err
	}
	// Write the partial lengths packet into 'raw'
	_, err = writeCloser.Write(plaintext)
	if err != nil {
		return nil, nil, err
	}
	// Close MUST be called - it appends the final auth. tag
	if err = writeCloser.Close(); err != nil {
		return nil, nil, err
	}
	// Packet is ready.
	return rawCipher, plaintext, nil
}

func readDecryptedStream(rc io.ReadCloser) (got []byte, err error) {
	for {
		// Read a random number of bytes, until the end of the packet.
		decrypted := make([]byte, mathrand.Intn(200))
		n, err := rc.Read(decrypted)
		decrypted = decrypted[:n]
		got = append(got, decrypted...)
		if err != nil {
			if err == io.EOF {
				// Finished reading
				break
			} else {
				// Something happened
				return nil, err
			}
		}
	}
	return got, err
}
