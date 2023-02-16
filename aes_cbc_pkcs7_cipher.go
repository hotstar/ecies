package ecies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type AesCbcPkcs7Cipher struct {
	iv []byte
}

func NewAesCbcPkcs7Cipher() *AesCbcPkcs7Cipher {
	return &AesCbcPkcs7Cipher{
		iv: make([]byte, 16), // IV For CBC, an IV filled with zero means no IV
	}
}

func (aesCbcPkcs7Cipher *AesCbcPkcs7Cipher) Encrypt(msg []byte, key []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	paddingMsg := pkcs7Pad(msg, aes.BlockSize())

	cipherMsg := make([]byte, len(paddingMsg))
	cbc := cipher.NewCBCEncrypter(aes, aesCbcPkcs7Cipher.iv)
	cbc.CryptBlocks(cipherMsg, paddingMsg)
	return cipherMsg, nil
}

func (aesCbcPkcs7Cipher *AesCbcPkcs7Cipher) Decrypt(encMsg []byte, key []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCDecrypter(aes, aesCbcPkcs7Cipher.iv)
	paddingMsg := make([]byte, len(encMsg))
	cbc.CryptBlocks(paddingMsg, encMsg)
	return pkcs7Unpad(paddingMsg)
}

func randomBytes(n int) []byte {
	bytes := make([]byte, n)
	rand.Read(bytes)
	return bytes
}
