package ecies

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHex(t *testing.T) {
	{
		msg := "hello"
		expected := "68656c6c6f"
		assert.Equal(t, expected, HexEncode([]byte(msg)))
	}
	{
		msg := "fdfdggsdgfda45qt"
		assert.Equal(t, msg, string(HexDecodeWithoutError(HexEncode([]byte(msg)))))
	}
	{
		msg := "{{{"
		assert.NotNil(t, HexEncode([]byte(msg)))
		assert.Nil(t, HexDecodeWithoutError(msg))

		decodeMsg, err := HexDecode(msg)
		assert.NotNil(t, err)
		assert.Nil(t, decodeMsg)
	}
}
