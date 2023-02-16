package ecies

import (
	"crypto/aes"
	"crypto/cipher"
)

type AesGcmCipher struct {
	nonce []byte
}

func NewAesGcmCipher() *AesGcmCipher {
	return &AesGcmCipher{
		nonce: make([]byte, 12),
	}
}

func (aesGcmCipher *AesGcmCipher) Encrypt(msg []byte, key []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, aesGcmCipher.nonce, msg, nil)
	return ciphertext, nil
}

func (aesGcmCipher *AesGcmCipher) Decrypt(encMsg []byte, key []byte) ([]byte, error) {
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(aes)
	if err != nil {
		return nil, err
	}
	plainMsg, err := gcm.Open(nil, aesGcmCipher.nonce, encMsg, nil)
	return plainMsg, nil
}
