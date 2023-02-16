package ecies

// KeyDerivationFunction the key derivation function that is used in the ECIES
type KeyDerivationFunction interface {
	GenerateKeyBytes(secret []byte, iv []byte, kenBytesLength int) ([]byte, error)
}
