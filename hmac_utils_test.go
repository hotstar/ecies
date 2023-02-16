package ecies

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHmacSha256(t *testing.T) {
	key := "6bfec41ca3e7bd0f4fff0235898fb678"
	{
		data := "82e0c393e2724184c31bb0452c222ce6"
		expectedMac := "773247df7352f8345819e78f0f5213cd6d61322f2fe730a04c83a2a88003e477"
		mac := HmacSha256(HexDecodeWithoutError(data), HexDecodeWithoutError(key), HexDecodeWithoutError("0000000000000000"))
		assert.Equal(t, expectedMac, HexEncode(mac))
	}
	{
		data := "hello"
		expectedMac := "6c9fbb15226fec10f3f33f2ac2972d3a9f98fd4e819b6cec9cfab64a7699ec70"
		mac := HmacSha256([]byte(data), HexDecodeWithoutError(key))
		assert.Equal(t, expectedMac, HexEncode(mac))
	}
}
