package ecies

// KeyAgreement the key agreement that is used in the ECIES
type KeyAgreement interface {
	CalculateAgreement(privateKey *PrivateKey, anotherPublicKey *PublicKey) ([]byte, error)
}
