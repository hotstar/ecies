package ecies

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

// We implement the key agreement following the section 7.2.2
// of this doc. https://perso.telecom-paristech.fr/guilley/recherche/cryptoprocesseurs/ieee/00891000.pdf

// calculateAgreement calculate a key following ECSVDP-DHC

func TestCalculateAgreement(t *testing.T) {
	privateBytes, err := hex.DecodeString("7819b30ff63ebd35f9fcf4233ccb7ecd8e9d90db8ec977cdf7b1f7bdc212b238")
	assert.Nil(t, err)

	privateKey := DeserializePrivateKey(privateBytes)
	assert.NotNil(t, privateKey)

	publicBytes, err := hex.DecodeString("040fe85dfc76083c4d3e9dda070df0ce6bc5b7a837c2b7975c32df26cca3f610725fa4d126cc2d0cc23762dbb199e5f7f4bc6281946f0086ef0800d288192aa1da")
	anotherPublicKey, err := DeserializePublicKey(publicBytes)
	assert.Nil(t, err)
	assert.NotNil(t, anotherPublicKey)

	expectedZ, err := hex.DecodeString("dbc1814beb81253bcd35b7bc51b968798df84843d384eefd539b05502178660d")
	assert.Nil(t, err)
	assert.NotNil(t, expectedZ)

	realZ, err := NewEcsvdpDhKeyAgreement().CalculateAgreement(privateKey, anotherPublicKey)
	assert.Nil(t, err)
	assert.NotNil(t, realZ)

	assert.Equal(t, string(expectedZ), string(realZ))

}

func TestCalculateAgreementWithInvalidParams(t *testing.T) {
	{
		realZ, err := NewEcsvdpDhKeyAgreement().CalculateAgreement(nil, nil)
		assert.Nil(t, realZ)
		assert.Equal(t, invalidEphemeralPublicKey, err)
	}
	{
		privateKey := &PrivateKey{}
		anotherPublicKey := &PublicKey{}
		realZ, err := NewEcsvdpDhKeyAgreement().CalculateAgreement(privateKey, anotherPublicKey)
		assert.Nil(t, realZ)
		assert.NotNil(t, err)
		assert.Equal(t, invalidEphemeralPublicKey, err)
	}
	{
		privateKey := &PrivateKey{}
		publicBytes, err := hex.DecodeString("040fe85dfc76083c4d3e9dda070df0ce6bc5b7a837c2b7975c32df26cca3f610725fa4d126cc2d0cc23762dbb199e5f7f4bc6281946f0086ef0800d288192aa1da")
		anotherPublicKey, err := DeserializePublicKey(publicBytes)
		assert.Nil(t, err)
		assert.NotNil(t, anotherPublicKey)
		realZ, err := NewEcsvdpDhKeyAgreement().CalculateAgreement(privateKey, anotherPublicKey)
		assert.Nil(t, realZ)
		assert.Equal(t, invalidPrivateKey, err)
	}
	{
		privateBytes, err := hex.DecodeString("7819b30ff63ebd35f9fcf4233ccb7ecd8e9d90db8ec977cdf7b1f7bdc212b238")
		assert.Nil(t, err)

		privateKey := DeserializePrivateKey(privateBytes)
		assert.NotNil(t, privateKey)
		privateKey.Curve = nil

		publicBytes, err := hex.DecodeString("040fe85dfc76083c4d3e9dda070df0ce6bc5b7a837c2b7975c32df26cca3f610725fa4d126cc2d0cc23762dbb199e5f7f4bc6281946f0086ef0800d288192aa1da")
		anotherPublicKey, err := DeserializePublicKey(publicBytes)
		assert.Nil(t, err)
		assert.NotNil(t, anotherPublicKey)

		realZ, err := NewEcsvdpDhKeyAgreement().CalculateAgreement(privateKey, anotherPublicKey)
		assert.Nil(t, realZ)
		assert.Equal(t, invalidPrivateKey, err)
	}
}
