package ecies

import (
	"bytes"
	"errors"
)

var (
	invalidEphemeralPublicKey = errors.New("ephemeral public key is invalid")
	invalidPrivateKey         = errors.New("private key is invalid")
)

// We implement the key agreement following the section 7.2.1 ECSVDP-DH
// of this doc. https://perso.telecom-paristech.fr/guilley/recherche/cryptoprocesseurs/ieee/00891000.pdf

type EcsvdpDhKeyAgreement struct {
}

func NewEcsvdpDhKeyAgreement() *EcsvdpDhKeyAgreement {
	return &EcsvdpDhKeyAgreement{}
}

// CalculateAgreement calculate a key following 1363 7.2.1 ECSVDP-DH
func (ka *EcsvdpDhKeyAgreement) CalculateAgreement(privateKey *PrivateKey, anotherPublicKey *PublicKey) ([]byte, error) {
	if anotherPublicKey == nil || anotherPublicKey.X == nil || anotherPublicKey.Y == nil {
		return nil, invalidEphemeralPublicKey
	}
	if privateKey == nil || privateKey.D == nil || privateKey.Curve == nil {
		return nil, invalidPrivateKey
	}

	var secret bytes.Buffer

	sx, _ := privateKey.Curve.ScalarMult(anotherPublicKey.X, anotherPublicKey.Y, privateKey.D.Bytes())

	// Sometimes shared secret coordinates are less than 32 bytes; Big Endian
	l := len(privateKey.Curve.Params().P.Bytes())
	secret.Write(zeroPad(sx.Bytes(), l))
	z := secret.Bytes()
	return z, nil
}

func zeroPad(b []byte, length int) []byte {
	for i := 0; i < length-len(b); i++ {
		b = append([]byte{0x00}, b...)
	}
	return b
}
