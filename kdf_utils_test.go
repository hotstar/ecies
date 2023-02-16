package ecies

import (
	"crypto"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKDF2GenerateKeyBytesWithSha256(t *testing.T) {
	kdf2 := NewKeyDerivationFunction2(crypto.SHA256)
	{
		secret := "04dfc571cbcd7b769937cc119d8ab2866828cb3de2b8c479d8a985f139af5c00c9bb62b77e19ca51a08cc7c0cef88a4bb650a8d43131a9b1ede560a9848299582aa4113634e7f7fcfd0734cdcfb69f3b98e0534d6016c14114ae01e4c7fe4cf40d"
		expectedBytes := "95b62e9d518340ed6b5670121bb2292348afe2bec6eb2569a3bb7018188b4895"
		derivedKeyBytes, err := kdf2.GenerateKeyBytes(HexDecodeWithoutError(secret), nil, crypto.SHA256.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
	{
		secret := "78074044e13f5ab41908a826f7b4f116464d686d33ee5eaee7e65f1ffdee5830fa94ec00f6b6f3c3a5bb9e882043369ba814bd6c17f168703f014305a71e3812b8ea4e6b77aa9fca45bdf973b26e65b5d887307fcafc5bbf027d"
		expectedBytes := "8c5a7b9352cbd333ee6124c24ea1e9a67807897ec4f92f5f6ab15731135ff81b"
		derivedKeyBytes, err := kdf2.GenerateKeyBytes(HexDecodeWithoutError(secret), nil, crypto.SHA256.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
	{
		secret := "f4f8ef483cc7ab0fcd025fbd8569e2f836ec8b84d840d73b7db0bc794f13c1179971677685660ae5f42c868adfb8b56304ec97bd6f0522845094ff64f5b017e0d38663a4c1b58324dcc4db85848dff9adae06b2b57439e9ab7ab"
		iv := "811589dfaae3a9ddb86d3b74b2374df8fd875a84124bb9f4433319ae7e163bca"
		expectedBytes := "df7fffbb625009b20d0fda61ac9736e87930708ecdbb275004ce3ddb417c02a8"
		derivedKeyBytes, err := kdf2.GenerateKeyBytes(HexDecodeWithoutError(secret), HexDecodeWithoutError(iv), crypto.SHA256.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
	{
		secret := "ac4bec1541a3c61f6b782a5dcd6d61ca8e1465658acbb8425f2051137bfe43fdc4e17c4d2799eb95169cefd681f2d446169d46a5c5b157337a016d6e1e9686cbe6ead44e6244d209472a16152795f41dedec95a7efa7fcbadd97"
		iv := "4e74de6f29fc9b2e30c03cc45740e955"
		expectedBytes := "d85491897816bbf97a83907329b0278b79b246b03f858ce3f7edf9c4506dd189"
		derivedKeyBytes, err := kdf2.GenerateKeyBytes(HexDecodeWithoutError(secret), HexDecodeWithoutError(iv), crypto.SHA256.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}

}

func TestKDF2GenerateKeyBytesWithSha1(t *testing.T) {
	kdf2 := NewKeyDerivationFunction2(crypto.SHA1)
	{
		secret := "f175a534f8f2d7e752cc81a09d8f96a4452862b3fad3ea5530561180f32efd0f381dec31ed39088799080cdeb579d606aa7dcd7f5e99cb202fdd26e2a03cc6abe6728e0771d6a27e7734e177fbf1d31e285918e5155f1d6304b6"
		iv := "ea8862b15e16bb3c7934d6c5d48e062a04ce0c9b"
		expectedBytes := "6dc9002f343daf8fb33d88b867b0d20aed785019"
		derivedKeyBytes, err := kdf2.GenerateKeyBytes(HexDecodeWithoutError(secret), HexDecodeWithoutError(iv), crypto.SHA1.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
	{
		secret := "8fd4ea0365c9e7e82fea6ca98d4b316ea80145a62d190e5587503d36b53c0274c92fcdbb8ea4e7ae267eabb653d5554eb3bb0bd5fb7c4c2000a57eb5e235f51b24243d031934a74e5a98cbda6014fa7f14499ab8b6e33e0db167"
		expectedBytes := "f53fb6bbb9b8fbaaebc241f3dacfd6e22e21c925"
		derivedKeyBytes, err := kdf2.GenerateKeyBytes(HexDecodeWithoutError(secret), nil, crypto.SHA1.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
}

func TestKDF1GenerateKeyBytesWithSha256(t *testing.T) {
	kdf1 := NewKeyDerivationFunction1(crypto.SHA256)
	{
		secret := "6ba16777ac63daab89b3e6cf6a8e3281fa33a6c580d82f5a6ce8396edb7b8960d95d61b758713656cc4dd1f438dd696f39fa4e97a223f4f7282beba2ce42ddaab8de6839d3ac95f64fc367662b713d99f30ca25c69a68fd91572"
		iv := "bdbe0d4d5fe9c4b62d56ee0e4371c283"
		expectedBytes := "c4f92a29c06875de373a3dd16993cb9f5d54587d23dd96ea1d90a77226159044"
		derivedKeyBytes, err := kdf1.GenerateKeyBytes(HexDecodeWithoutError(secret), HexDecodeWithoutError(iv), crypto.SHA256.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
	{
		secret := "c96ad0d35a2dc6d191257ee9b6bfd3770eb18e8bcc4144a4dc1fe5bae4558c9b4d20e878208f344948c877c424434744eb1991768a3838dd0686c9ff1e94471fdf59ac362d8ac530f0875275784e0fb17227d70b88d4d842f06c"
		expectedBytes := "d86a39f8433f86caa07ffa8c81d8a3a1b12fedb9ef2cbc358443f7b265e8aeb8"
		derivedKeyBytes, err := kdf1.GenerateKeyBytes(HexDecodeWithoutError(secret), nil, crypto.SHA256.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
}

func TestKDF1GenerateKeyBytesWithSha1(t *testing.T) {
	kdf1 := NewKeyDerivationFunction1(crypto.SHA1)
	{
		secret := "8516ab3191f605b018d715aca43ea956fff74aa97a8929e494e3c2f043177834c836772e0ae0af2c1ea19628dd3666a15eb607d5505b69c2dacb9d663171c5527d9128d45acf86bbf636f00103d26c90c4a7902a0b2a45c5eb4c"
		iv := "0c5224b097e1e0583133ac6302d0517f"
		expectedBytes := "2d1310e5b95264bdaa9563e50c2f1f28c9cfb050"
		derivedKeyBytes, err := kdf1.GenerateKeyBytes(HexDecodeWithoutError(secret), HexDecodeWithoutError(iv), crypto.SHA1.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
	{
		secret := "e9bdf54e281280159fd4e96e0efe2d142578e4ca23d3dabc7f17af9290ec510a9796767806bb9750964477646a3b5f40b26110ea60a05604f80dcc2b83fd1362de29a01085e11351a112dc3095b4c77ab387726ab67226dfcc3b"
		expectedBytes := "2af363f6a15af99f47d24441827fa0f71f23b50b"
		derivedKeyBytes, err := kdf1.GenerateKeyBytes(HexDecodeWithoutError(secret), nil, crypto.SHA1.Size())
		assert.Nil(t, err)
		assert.Equal(t, expectedBytes, HexEncode(derivedKeyBytes))
	}
}
