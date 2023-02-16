package ecies

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"math/big"
)

type PublicKey struct {
	elliptic.Curve
	X *big.Int
	Y *big.Int
}

type PrivateKey struct {
	*PublicKey
	D *big.Int
}

// GenerateKey generate an ECC key pair
func GenerateKey() (*PrivateKey, error) {
	d, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(d),
	}, nil
}

// SerializePrivateKey Serialize the D bytes of the private key
func SerializePrivateKey(privateKey *PrivateKey) []byte {
	return privateKey.D.Bytes()
}

// DeserializePrivateKey Deserialize from the D bytes
func DeserializePrivateKey(dBytes []byte) *PrivateKey {
	d := new(big.Int).SetBytes(dBytes)
	x, y := curve.ScalarBaseMult(dBytes)
	return &PrivateKey{
		PublicKey: &PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: d,
	}
}

// SerializePublicKey Serialize the X,Y bytes of the public key
func SerializePublicKey(publicKey *PublicKey) []byte {
	return elliptic.Marshal(curve, publicKey.X, publicKey.Y)
}

// DeserializePublicKey Deserialize from the X,Y bytes
func DeserializePublicKey(pointBytes []byte) (*PublicKey, error) {
	x, y := elliptic.Unmarshal(curve, pointBytes)
	if x == nil || y == nil {
		return nil, fmt.Errorf("invalid public key")
	}
	return &PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// DeserializePublicKeyFromCoordinate Deserialize from the X,Y coordinate string
func DeserializePublicKeyFromCoordinate(xCoordinate, yCoordinate string) (*PublicKey, error) {
	x, ok := new(big.Int).SetString(xCoordinate, 10)
	if !ok {
		return nil, fmt.Errorf("invalid x coordinate")
	}
	y, ok := new(big.Int).SetString(yCoordinate, 10)
	if !ok {
		return nil, fmt.Errorf("invalid y coordinate")
	}
	return &PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}, nil
}

// SerializePublicKeyToCoordinate Serialize the X,Y coordinate string
func SerializePublicKeyToCoordinate(publicKey *PublicKey) (string, string) {
	return publicKey.X.Text(10), publicKey.Y.Text(10)
}
