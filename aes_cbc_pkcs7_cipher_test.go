package ecies

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// The data is only for test
func TestAESCBCPkcs7(t *testing.T) {
	aesCbcPkcs7Cipher := NewAesCbcPkcs7Cipher()
	{
		secret := HexDecodeWithoutError("76958f76e00d653442d8f0ef4c4b257a")
		data := HexDecodeWithoutError("b37f70310e637e77ee10eacc5896e5f0")
		msg, err := aesCbcPkcs7Cipher.Decrypt(data, secret)
		assert.Nil(t, err)
		assert.Equal(t, "Hello world", string(msg))
	}
	{
		msg := "good"
		key := randomBytes(16)

		encMsg, err := aesCbcPkcs7Cipher.Encrypt([]byte(msg), key)
		assert.Nil(t, err)
		plainMsg, err := aesCbcPkcs7Cipher.Decrypt(encMsg, key)
		assert.Nil(t, err)
		assert.Equal(t, msg, string(plainMsg))
	}
}
