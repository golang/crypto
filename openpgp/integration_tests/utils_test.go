package integrationtests

import (
	"time"
	"bytes"
	"crypto"
	"crypto/rand"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	mathrand "math/rand"
	"strings"
)


// This function produces random test vectors: generates keys according to the
// given settings, associates a random message for each key. It returns the
// test vectors.
func generateFreshTestVectors() (vectors []testVector, err error) {
	mathrand.Seed(time.Now().UTC().UnixNano())
	for i := 0; i < 3; i++ {
		config := randConfig()
		// Sample random email, comment, password and message
		name, email, comment, password, message := randEntityData()

		// Only for verbose display
		pkAlgoNames := map[packet.PublicKeyAlgorithm]string {
			packet.PubKeyAlgoRSA: "rsa_fresh",
			packet.PubKeyAlgoEdDSA: "ed25519_fresh",
		}

		newVector := testVector{
			config:   config,
			Name:     pkAlgoNames[config.Algorithm],
			Password: password,
			Message:  message,
		}

		// Generate keys
		newEntity, errKG := openpgp.NewEntity(name, comment, email, config)
		if errKG != nil {
			panic(errKG)
		}
		if err = newEntity.SelfSign(nil); err != nil {
			panic(err)
		}

		// Encrypt private key of entity
		rawPwd := []byte(password)
		if newEntity.PrivateKey != nil && !newEntity.PrivateKey.Encrypted {
			if err = newEntity.PrivateKey.Encrypt(rawPwd); err != nil {
				panic(err)
			}
		}

		// Encrypt subkeys of entity
		for _, sub := range newEntity.Subkeys {
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err = sub.PrivateKey.Encrypt(rawPwd); err != nil {
					panic(err)
				}
			}
		}

		w := bytes.NewBuffer(nil)
		if err = newEntity.SerializePrivateNoSign(w, nil); err != nil {
			return nil, err
		}

		serialized := w.Bytes()

		privateKey, _ := armorWithType(serialized, "PGP PRIVATE KEY BLOCK")
		newVector.PrivateKey = privateKey
		newVector.PublicKey, _ = publicKey(privateKey)

		vectors = append(vectors, newVector)
	}
	return vectors, err
}

// armorWithType make bytes input to armor format
func armorWithType(input []byte, armorType string) (string, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, armorType, nil)
	if err != nil {
		return "", err
	}
	if _, err = w.Write(input); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return b.String(), nil
}

func publicKey(privateKey string) (string, error) {
	privKeyReader := strings.NewReader(privateKey)
	entries, err := openpgp.ReadArmoredKeyRing(privKeyReader)
	if err != nil {
		return "", err
	}

	var outBuf bytes.Buffer
	for _, e := range entries {
		err := e.Serialize(&outBuf)
		if err != nil {
			return "", err
		}
	}

	outString, err := armorWithType(outBuf.Bytes(), "PGP PUBLIC KEY BLOCK")
	if err != nil {
		return "", err
	}

	return outString, nil
}

var runes = []rune("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKMNOPQRSTUVWXYZ.:;?/!@#$%^&*{}[]_'\"-+~()<>")

func randName() string {
	firstName := make([]rune, 8)
	lastName := make([]rune, 8)
	nameRunes := runes[:26]

	for i := range firstName {
		firstName[i] = nameRunes[mathrand.Intn(len(nameRunes))]
	}

	for i := range lastName {
		lastName[i] = nameRunes[mathrand.Intn(len(nameRunes))]
	}

	return string(firstName) + " " + string(lastName)
}

func randEmail() string {
	address := make([]rune, 20)
	addressRunes := runes[:38]
	domain := make([]rune, 5)
	domainRunes := runes[:36]
	ext := make([]rune, 3)
	for i := range address {
		address[i] = addressRunes[mathrand.Intn(len(addressRunes))]
	}
	for i := range domain {
		domain[i] = domainRunes[mathrand.Intn(len(domainRunes))]
	}
	for i := range ext {
		ext[i] = domainRunes[mathrand.Intn(len(domainRunes))]
	}
	email := string(address) + "@" + string(domain) + "." + string(ext)
	return email
}

// Comment does not allow the following characters: ()<>\x00
func randComment() string {
	comment := make([]rune, 140)
	commentRunes := runes[:84]
	for i := range comment {
		comment[i] = commentRunes[mathrand.Intn(len(commentRunes))]
	}
	return string(comment)
}

func randPassword() string {
	maxPasswordLength := 64
	password := make([]rune, mathrand.Intn(maxPasswordLength-1)+1)
	for i := range password {
		password[i] = runes[mathrand.Intn(len(runes))]
	}
	return string(password)
}

func randMessage() string {
	maxMessageLength := 1 << 12
	message := make([]byte, 1+mathrand.Intn(maxMessageLength-1))
	if _, err := rand.Read(message); err != nil {
		panic(err)
	}
	return string(message)
}

// Change one char of the input
func corrupt(input string) string {
	if input == "" {
		return string(runes[mathrand.Intn(len(runes))])
	}
	output := []rune(input)
	for string(output) == input {
		output[mathrand.Intn(len(output))] = runes[mathrand.Intn(len(runes))]
	}
	return string(output)
}

func randEntityData() (string, string, string, string, string) {
	return randName(), randEmail(), randComment(), randPassword(), randMessage()
}

func randConfig() *packet.Config {
	hashes := []crypto.Hash{
		crypto.SHA256,
	}
	hash := hashes[mathrand.Intn(len(hashes))]

	ciphers := []packet.CipherFunction{
		packet.CipherAES256,
	}
	ciph := ciphers[mathrand.Intn(len(ciphers))]

	compAlgos := []packet.CompressionAlgo {
		packet.CompressionNone,
		packet.CompressionZIP,
		packet.CompressionZLIB,
	}
	compAlgo := compAlgos[mathrand.Intn(len(compAlgos))]

	pkAlgos := []packet.PublicKeyAlgorithm {
		packet.PubKeyAlgoRSA,
		packet.PubKeyAlgoEdDSA,
	}
	pkAlgo := pkAlgos[mathrand.Intn(len(pkAlgos))]


	var rsaBits int
	if pkAlgo == packet.PubKeyAlgoRSA {
		switch mathrand.Int() % 4 {
		case 0:
			rsaBits = 2048
		case 1:
			rsaBits = 3072
		case 2:
			rsaBits = 4096
		default:
			rsaBits = 0
		}
	}

	level := mathrand.Intn(11)-1
	compConf := &packet.CompressionConfig{level}

	// Define AEAD mode when it's implemented
	return &packet.Config{
		Rand: rand.Reader,
		DefaultHash: hash,
		DefaultCipher: ciph,
		DefaultCompressionAlgo: compAlgo,
		CompressionConfig: compConf,
		S2KCount: 1024 + mathrand.Intn(65010689),
		RSABits: rsaBits,
		Algorithm: pkAlgo,
	}
}
