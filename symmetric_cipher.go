package ecies

// SymmetricCipher the symmetric cipher that is used in the ECIES
type SymmetricCipher interface {
	Encrypt(msg []byte, key []byte) ([]byte, error)
	Decrypt(encMsg []byte, key []byte) ([]byte, error)
}
