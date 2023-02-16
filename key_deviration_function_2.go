package ecies

import "crypto"

type KeyDerivationFunction2 struct {
	inputHash crypto.Hash
}

func NewKeyDerivationFunction2(inputHash crypto.Hash) *KeyDerivationFunction2 {
	return &KeyDerivationFunction2{inputHash: inputHash}
}

func (keyDerivationFunction2 KeyDerivationFunction2) GenerateKeyBytes(secret []byte, iv []byte, kenBytesLength int) ([]byte, error) {
	kdf, err := newKDF2(secret, iv, keyDerivationFunction2.inputHash, kenBytesLength)
	if err != nil {
		return nil, err
	}
	keyBytes := make([]byte, kenBytesLength)
	kdf.read(keyBytes)
	return keyBytes, nil
}
