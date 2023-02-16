package ecies

import (
	"crypto/elliptic"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestCurve(t *testing.T) {
	{
		assert.Equal(t, "P-256", GetCurve().Params().Name)
		assert.Equal(t, 65, GetECPointByteLength())
	}
	{
		SetCurve(elliptic.P384())
		assert.Equal(t, "P-384", GetCurve().Params().Name)
		assert.Equal(t, 97, GetECPointByteLength())
		ClearCurve()
		assert.Equal(t, "P-256", GetCurve().Params().Name)
		assert.Equal(t, 65, GetECPointByteLength())
	}
	{
		SetCurve(elliptic.P521())
		assert.Equal(t, "P-521", GetCurve().Params().Name)
		assert.Equal(t, 133, GetECPointByteLength())
		ClearCurve()
		assert.Equal(t, "P-256", GetCurve().Params().Name)
		assert.Equal(t, 65, GetECPointByteLength())
	}
	{
		ClearCurve()
		assert.Equal(t, "P-256", GetCurve().Params().Name)
		assert.Equal(t, 65, GetECPointByteLength())
	}
}
