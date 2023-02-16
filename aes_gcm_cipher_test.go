package ecies

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

// The data is only for test
func TestAESGCM(t *testing.T) {
	aesGcm := NewAesGcmCipher()
	{
		msg := "good"
		key := randomBytes(16)

		encMsg, err := aesGcm.Encrypt([]byte(msg), key)
		assert.Nil(t, err)
		plainMsg, err := aesGcm.Decrypt(encMsg, key)
		assert.Nil(t, err)
		assert.Equal(t, msg, string(plainMsg))
	}
	{
		msg := "Hello_world"
		key := HexDecodeWithoutError("32c764f6a5946ec8d9ba1c95647851f9")
		plainMsg, err := aesGcm.Decrypt(HexDecodeWithoutError("ac4d04354fdbb3941a85375223d9a785e6788581f1e1d043c220d9"), key)
		assert.Nil(t, err)
		assert.Equal(t, msg, string(plainMsg))
	}
	{
		msg := "good"
		key := []byte("123")

		encMsg, err := aesGcm.Encrypt([]byte(msg), key)
		assert.NotNil(t, err)
		assert.Nil(t, encMsg)
	}
	{
		key := []byte("123")
		plainMsg, err := aesGcm.Decrypt(HexDecodeWithoutError("ac4d04354fdbb3941a85375223d9a785e6788581f1e1d043c220d9"), key)
		assert.NotNil(t, err)
		assert.Nil(t, plainMsg)
	}
}
