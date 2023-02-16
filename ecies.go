package ecies

import (
	"bytes"
	"crypto"
	"fmt"
)

// We implement ECIES (shoup version) following the specification IEEE Std 1363 a
// https://www.shoup.net/papers/iso-2_1.pdf

// Can interact with Crypto++ Botan and Bouncy Castle
// https://www.cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme

type ECIES struct {
	keyAgreement          KeyAgreement
	keyDerivationFunction KeyDerivationFunction
	symmetricCipher       SymmetricCipher
	hmacHash              crypto.Hash
	encKeyByteSize        int
	macKeyByteSize        int
	ecPointByteSize       int
}

// NewECIES create an ECIES instance with default algorithms
func NewECIES() *ECIES {
	kdf2 := NewKeyDerivationFunction2(crypto.SHA256)
	return NewCustomizedECIES(NewEcsvdpDhKeyAgreement(), NewAesCbcPkcs7Cipher(), kdf2, crypto.SHA256, 16, 16)
}

// NewCustomizedECIES create an ECIES instance with customized algorithms
func NewCustomizedECIES(ka KeyAgreement, cipher SymmetricCipher, kdf KeyDerivationFunction, hmacHash crypto.Hash, encKeyByteSize int, macKeyByteSize int) *ECIES {
	return &ECIES{
		keyAgreement:          ka,
		keyDerivationFunction: kdf,
		symmetricCipher:       cipher,
		hmacHash:              hmacHash,
		encKeyByteSize:        encKeyByteSize,
		macKeyByteSize:        macKeyByteSize,
		ecPointByteSize:       GetECPointByteLength(),
	}
}

// Encrypt encrypts a passed message with a receiver public key, returns ciphertext or encryption error
func (ecies *ECIES) Encrypt(pubkey *PublicKey, msg []byte) ([]byte, error) {
	// Message cannot be empty
	if msg == nil || len(msg) == 0 {
		return nil, fmt.Errorf("invalid length of message")
	}
	var ct bytes.Buffer

	// Generate ephemeral key
	ephemeralPrivateKey, err := GenerateKey()
	if err != nil {
		return nil, err
	}
	ct.Write(SerializePublicKey(ephemeralPrivateKey.PublicKey))

	// Derive shared secret
	z, err := ecies.keyAgreement.CalculateAgreement(ephemeralPrivateKey, pubkey)
	if err != nil {
		return nil, err
	}
	// Create the input kdfZ of kdf
	var kdfZ bytes.Buffer
	kdfZ.Write(SerializePublicKey(ephemeralPrivateKey.PublicKey))
	kdfZ.Write(z)

	kenLen := ecies.encKeyByteSize + ecies.macKeyByteSize
	derivedKeyBytes, err := ecies.keyDerivationFunction.GenerateKeyBytes(kdfZ.Bytes(), nil, kenLen)
	if err != nil || (len(derivedKeyBytes) != kenLen) {
		return nil, err
	}
	encKey := derivedKeyBytes[:ecies.encKeyByteSize]
	macKey := derivedKeyBytes[ecies.encKeyByteSize:kenLen]

	//Generate enc message
	encBytes, err := ecies.symmetricCipher.Encrypt(msg, encKey)
	if err != nil {
		return nil, err
	}
	ct.Write(encBytes)

	// Generate the mac
	l2 := getLengthTag(nil)
	macBytes := Hmac(ecies.hmacHash, encBytes, macKey, l2)
	ct.Write(macBytes)

	return ct.Bytes(), nil
}

// Decrypt decrypts a passed message with a receiver private key, returns plaintext or decryption error
func (ecies *ECIES) Decrypt(privateKey *PrivateKey, msg []byte) ([]byte, error) {
	// Message cannot be less than length of public key +  mac, because the cipher msg length > 0
	if len(msg) <= (ecies.ecPointByteSize + ecies.hmacHash.Size()) {
		return nil, fmt.Errorf("invalid length of message")
	}

	// Parse ephemeral sender public key in no compression mode
	ephemeralPublicKey, err := DeserializePublicKey(msg[:ecies.ecPointByteSize])
	if err != nil {
		return nil, err
	}
	// Read mac and enc message
	macStart := len(msg) - ecies.hmacHash.Size()
	macBytes := msg[macStart:]
	encBytes := msg[ecies.ecPointByteSize:macStart]

	// Derive shared secret
	z, err := ecies.keyAgreement.CalculateAgreement(privateKey, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	// Create the input kdfZ of kdf
	var kdfZ bytes.Buffer
	kdfZ.Write(SerializePublicKey(ephemeralPublicKey))
	kdfZ.Write(z)

	kenLen := ecies.encKeyByteSize + ecies.macKeyByteSize

	derivedKeyBytes, err := ecies.keyDerivationFunction.GenerateKeyBytes(kdfZ.Bytes(), nil, kenLen)
	if err != nil || (len(derivedKeyBytes) != kenLen) {
		return nil, err
	}
	encKey := derivedKeyBytes[:ecies.encKeyByteSize]
	macKey := derivedKeyBytes[ecies.encKeyByteSize:kenLen]

	// Compare the mac
	l2 := getLengthTag(nil)
	macBytes2Compare := Hmac(ecies.hmacHash, encBytes, macKey, l2)
	if !bytesEquals(macBytes, macBytes2Compare) {
		return nil, fmt.Errorf("invalid mac data")
	}

	// Decrypt the enc message
	plainBytes, err := ecies.symmetricCipher.Decrypt(encBytes, encKey)
	if err != nil {
		return nil, fmt.Errorf("invalid enc data")
	}
	return plainBytes, nil
}

func bytesEquals(b1 []byte, b2 []byte) bool {
	if b1 == nil && b2 == nil {
		return true
	}
	if b1 == nil || b2 == nil {
		return false
	}
	return string(b1) == string(b2)
}

// as described in Shoup's paper and P1363a
func getLengthTag(p2 []byte) []byte {
	l2 := make([]byte, 8)
	//if (p2 != nil) {
	//	Pack.longToBigEndian(p2.length * 8L, L2, 0)
	//}
	return l2
}
