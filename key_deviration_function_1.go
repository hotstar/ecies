package ecies

import "crypto"

type KeyDerivationFunction1 struct {
	inputHash crypto.Hash
}

func NewKeyDerivationFunction1(inputHash crypto.Hash) *KeyDerivationFunction1 {
	return &KeyDerivationFunction1{inputHash: inputHash}
}

func (keyDerivationFunction1 KeyDerivationFunction1) GenerateKeyBytes(secret []byte, iv []byte, kenBytesLength int) ([]byte, error) {
	kdf, err := newKDF1(secret, iv, keyDerivationFunction1.inputHash, kenBytesLength)
	if err != nil {
		return nil, err
	}
	keyBytes := make([]byte, kenBytesLength)
	kdf.read(keyBytes)
	return keyBytes, nil
}
