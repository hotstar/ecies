package ecies

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDefaultECIESFlow(t *testing.T) {
	{
		k, err := GenerateKey()
		if err != nil {
			t.Error("failed to generate key pair")
		}
		privateKey := k
		publicKey := k.PublicKey

		serializedPrivateKey := HexEncode(SerializePrivateKey(privateKey))
		serializedPublicKey := HexEncode(SerializePublicKey(publicKey))
		fmt.Println("privateKey=" + serializedPrivateKey)
		fmt.Println("publicKey=" + serializedPublicKey)

		deserializedPrivateKey := DeserializePrivateKey(HexDecodeWithoutError(serializedPrivateKey))
		deserializedPublicKey, err := DeserializePublicKey(HexDecodeWithoutError(serializedPublicKey))
		if err != nil {
			t.Error("failed to deserialize key pair")
		}
		assert.True(t, deserializedPrivateKey.D.Cmp(privateKey.D) == 0)
		assert.True(t, deserializedPublicKey.X.Cmp(publicKey.X) == 0)
		assert.True(t, deserializedPublicKey.Y.Cmp(publicKey.Y) == 0)

		ecies := NewECIES()
		plainText := "hello+world"
		encryptedTextBytes, err := ecies.Encrypt(publicKey, []byte(plainText))
		if err != nil {
			t.Error("failed to encrypt message")
		}
		fmt.Println(HexEncode(encryptedTextBytes))
		decryptedTextBytes, err := ecies.Decrypt(privateKey, encryptedTextBytes)
		if err != nil {
			t.Error("failed to decrypt message")
		}
		assert.Equal(t, plainText, string(decryptedTextBytes))
	}
}

func TestDifferentCurve(t *testing.T) {
	{
		SetCurve(elliptic.P256())
		k, err := GenerateKey()
		if err != nil {
			t.Error("failed to generate key")
		}
		privateKey := k
		publicKey := k.PublicKey
		ecies := NewECIES()
		assert.Equal(t, GetECPointByteLength(), ecies.ecPointByteSize)
		plainText := "hello world"
		encryptedTextBytes, err := ecies.Encrypt(publicKey, []byte(plainText))
		if err != nil {
			t.Error("failed to encrypt message")
		}
		decryptedTextBytes, err := ecies.Decrypt(privateKey, encryptedTextBytes)
		if err != nil {
			t.Error("failed to decrypt message")
		}
		assert.Equal(t, plainText, string(decryptedTextBytes))
		ClearCurve()
	}
	{
		SetCurve(elliptic.P384())
		k, err := GenerateKey()
		if err != nil {
			t.Error("failed to generate key")
		}
		privateKey := k
		publicKey := k.PublicKey
		ecies := NewECIES()
		assert.Equal(t, GetECPointByteLength(), ecies.ecPointByteSize)
		plainText := "hello world"
		encryptedTextBytes, err := ecies.Encrypt(publicKey, []byte(plainText))
		if err != nil {
			t.Error("failed to encrypt message")
		}
		decryptedTextBytes, err := ecies.Decrypt(privateKey, encryptedTextBytes)
		if err != nil {
			t.Error("failed to decrypt message")
		}
		assert.Equal(t, plainText, string(decryptedTextBytes))
		ClearCurve()
	}
	{
		SetCurve(elliptic.P521())
		k, err := GenerateKey()
		if err != nil {
			t.Error("failed to generate key")
		}
		privateKey := k
		publicKey := k.PublicKey
		ecies := NewECIES()
		assert.Equal(t, GetECPointByteLength(), ecies.ecPointByteSize)
		plainText := "hello world"
		encryptedTextBytes, err := ecies.Encrypt(publicKey, []byte(plainText))
		if err != nil {
			t.Error("failed to encrypt message")
		}
		decryptedTextBytes, err := ecies.Decrypt(privateKey, encryptedTextBytes)
		if err != nil {
			t.Error("failed to decrypt message")
		}
		assert.Equal(t, plainText, string(decryptedTextBytes))
		ClearCurve()
	}
}

func TestCompatibilityWithBouncyCastle(t *testing.T) {
	{
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("344b09adcd5048f7f2e83bdabc155587c0071769b86c4715137e8fd06e30f349"))
		ecies := NewECIES()
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("04cc3c7e86f5e2771a299b81038f67105ce5aee397513da5775a6748ec6335ff3c360f291df1fe97066cad2b4300fcef06162c571052097f40e842e2c884356bfeb4a3c6d60f78297cf2be5e5a1d7319b08188560603924534fc8211b28bbead8404ab438e54093ba52977327226bc4034"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello=world")
	}
	{
		SetCurve(elliptic.P384())
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("cfd0e0017542dbdee76fb2c0c89230d16cf874c09b54d6f454e9180660aba1b135ea332675054fe3bc7a0aee6ccde68b"))
		ecies := NewECIES()
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("04b4cc0518bd6ddff36d33bd55cdf6c0040a963fa104cf0dc1d373148671e318b133038c518339be10b41fd4daa5aa42b1cf4b5948dff628f830cac9a67151721af0f3179350a00fb62184c5f3037d4c502e97bfa48d3b68f83193b97de7769e842eb8f124843c980a1b6e2300b9a540b4c62d25b51f4008542b27425339cbd3efd51c363264b980e95b91dd3bf5e21619"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello=world")
		ClearCurve()
	}
	{
		SetCurve(elliptic.P521())
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("01b0ffc246bf9ae9bf5be2112128be6c19bb86b1bd7925bea2cf2269fda5c092a8d5c9d2353699bab4d2875ab8a5f7e1f0f281d66e2de39b6c0e4e03f2c047575533"))
		ecies := NewECIES()
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("04004dc58256ba58cb7458c58e6dec6c49db4001d992bc058c255a6409c8ea88e9761c7f055d6d15e79b2aa0d5fb8b1b39287b4829643f4d34c12567ab07fec5b212ea01ab9f2749717c457371d07fa974e4c04fc493bf2c9aacdd8eb398c7f65c5f2691a51645dd89f24a74ad9bc894da334f93fe5fd59aa1661d767a531b77093d4a7a3be6206e0561c3adc18c40d7445944e1a4731baf0c302eb0a9e3ec28ab03197fe228eb2905f9777167d81e6b0b0191410d"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello=world")
		ClearCurve()
	}
	{
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("19f209fc65430e95fda48dbe673bc68309535584f65bc594371fc350334074ef"))
		ecies := NewCustomizedECIES(NewEcsvdpDhKeyAgreement(), NewAesCbcPkcs7Cipher(), NewKeyDerivationFunction1(crypto.SHA256), crypto.SHA256, 16, 16)
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("047832308176f607eb497ac3296b0c4c312f2ca100a1a29fa1fcc23b7826dd3b51ac5cb3549112dba608d2fcf3428183b4e1ba90fbfa35a22ae388c29f49a6cfc79b073bc6acd2a9940942b252d0814eaf032b04ead264c660b977d9f57d7093f5e14d7d48ce255093f26ae24eba43cb19"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello+world")
	}
	{
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("16559c42d4e9f20d6e4815306edf9c17201fa5d913c38d7c164f186c5207aaa2"))
		ecies := NewCustomizedECIES(NewEcsvdpDhKeyAgreement(), NewAesCbcPkcs7Cipher(), NewKeyDerivationFunction1(crypto.SHA1), crypto.SHA1, 16, 16)
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("042b2118348b6677161a6f007099c711b1690bab89ff2b27d656ae1230da71f2a7d5f19648c8785aa898965ad9818a03927c4384d9b0058be19d3756f5fca6d5d966563fedeef48ec3f481180fbbf1377473d34042d9fb2f77718dcf17024c66ba1bd257e1"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello+world")
	}
	{
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("f1e99bae75f88b1bdd24303c3d484bbe85c9dc51382807d16e67e629318e96ea"))
		ecies := NewCustomizedECIES(NewEcsvdpDhKeyAgreement(), NewAesCbcPkcs7Cipher(), NewKeyDerivationFunction1(crypto.SHA384), crypto.SHA384, 16, 16)
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("047b884885216a606b3174b11ea30d99abac46e800d0dead8d112d3766f39115a831bd04577c8e5d2bf5bf20a0790ee5c1708cfe1de9c3920a406c90f751a89a97644f7f60a5b358a798a75f5d440b4952fdfd82e9ecc126f853700aa925d49ccccdfa7f0aa3d35ebad14248502c588ccda29cb1c9b3ba6390e89b317c3d8d86bc"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello+world")
	}
	{
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("6ed14bb52c36ef2b7aae22e65ce08cfd0aaa09b930d3e949c39c3f845795b1bf"))
		ecies := NewCustomizedECIES(NewEcsvdpDhKeyAgreement(), NewAesCbcPkcs7Cipher(), NewKeyDerivationFunction1(crypto.SHA512), crypto.SHA512, 16, 16)
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("04916cf1c52d9bad46a59d26fe054d61936c020363163e53258b512f207327f9e859d9a1717e969e7e11862cf61afb3d4e809ff9b9b377bbd51eb3dcd22dc52f0b83aca53430381e051cc8094fa14940d49984c742835c70c1a784577faf788ebbee6e508d255e20c54e3a1a74c2cd9935f8bf341145d98272d0c02679e29a32d4ff246b7cdf9c11f818583d8316bcf03b"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello+world")
	}
	{
		privateKey := DeserializePrivateKey(HexDecodeWithoutError("a80b542432050d3344f173a1aa21c8d3fb1a4abfeb0159f2c472625e6dbc257d"))
		ecies := NewCustomizedECIES(NewEcsvdpDhKeyAgreement(), NewAesGcmCipher(), NewKeyDerivationFunction1(crypto.SHA256), crypto.SHA256, 16, 16)
		plainBytes, err := ecies.Decrypt(privateKey, HexDecodeWithoutError("04843fc3d6fb3691b5f1e2685308b2b53276a9e6b1634542a743ebf59ae140bda7b70bcf8b74589ad2565607a8a22c72455a29d9428fe8249ca0dbad2f208b40f3df8188864e0bb11b051731514a8e3a486364205933e4fc7c58d2e6228561c94289f76fdb364c7df28349032854ef4f049bce632b90f64fe93dac32"))
		assert.Nil(t, err)
		assert.Equal(t, string(plainBytes), "Hello=world")
	}

}

func TestErrorDecryption(t *testing.T) {
	privateKeyString := "842095a3282fb0493bca0ba93a21e11f69aa93c53202cadab9b7fd8cb195d9ab"
	encMessageString := "04fadecd20f9a4ccd2275592c8b1c8c544afb6188d452876579169a3cf7c36d7e5a74de8f25a10f785f481df46e0ab1a1a36380cca500c48e476d464985918870d0b080cb5eb4b5211f3b000ccaf9cc957d5c0ffce21fb771e12082ff9a723a3c10d85ff0ee040f4d1f79c568282dbb7cc"

	privateKey := DeserializePrivateKey(HexDecodeWithoutError(privateKeyString))
	ecies := NewECIES()
	encMessage := HexDecodeWithoutError(encMessageString)
	plainMessage, err := ecies.Decrypt(privateKey, encMessage)
	assert.Nil(t, err)
	assert.Equal(t, "hello_world", string(plainMessage))

	// enc message is too short
	{
		plainMessage, err := ecies.Decrypt(privateKey, encMessage[:65])
		assert.NotNil(t, err)
		assert.Nil(t, plainMessage)
	}
	// enc message is too short
	{
		plainMessage, err := ecies.Decrypt(privateKey, encMessage[:len(encMessage)-31])
		assert.NotNil(t, err)
		assert.Nil(t, plainMessage)
	}
	// invalid ephemeral public key
	{
		encMessage[0] = 3
		plainMessage, err := ecies.Decrypt(privateKey, encMessage)
		assert.NotNil(t, err)
		assert.Nil(t, plainMessage)
		encMessage[0] = 4
	}
	// invalid privateKey
	{
		plainMessage, err := ecies.Decrypt(nil, encMessage)
		assert.NotNil(t, err)
		assert.Nil(t, plainMessage)
	}
	// invalid mac
	{
		plainMessage, err := ecies.Decrypt(privateKey, encMessage[:len(encMessage)-1])
		assert.NotNil(t, err)
		assert.Nil(t, plainMessage)
	}
}

func TestErrorEncryption(t *testing.T) {
	{
		k, err := GenerateKey()
		if err != nil {
			t.Error("failed to generate key pair")
		}
		privateKey := k
		publicKey := k.PublicKey
		assert.NotNil(t, privateKey)
		assert.NotNil(t, publicKey)

		ecies := NewECIES()
		plainText := "hello+world"
		encryptedTextBytes, err := ecies.Encrypt(nil, []byte(plainText))
		assert.Nil(t, encryptedTextBytes)
		assert.NotNil(t, err)
	}
	{
		k, err := GenerateKey()
		if err != nil {
			t.Error("failed to generate key pair")
		}
		privateKey := k
		publicKey := k.PublicKey
		assert.NotNil(t, privateKey)
		assert.NotNil(t, publicKey)

		ecies := NewECIES()
		encryptedTextBytes, err := ecies.Encrypt(publicKey, nil)
		assert.Nil(t, encryptedTextBytes)
		assert.NotNil(t, err)
	}
	{
		k, err := GenerateKey()
		if err != nil {
			t.Error("failed to generate key pair")
		}
		privateKey := k
		publicKey := k.PublicKey
		assert.NotNil(t, privateKey)
		assert.NotNil(t, publicKey)

		ecies := NewECIES()
		encryptedTextBytes, err := ecies.Encrypt(publicKey, make([]byte, 0))
		assert.Nil(t, encryptedTextBytes)
		assert.NotNil(t, err)
	}
}
