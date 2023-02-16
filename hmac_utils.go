package ecies

import (
	"crypto"
	"crypto/hmac"
)

func HmacSha256(data []byte, secret []byte, otherDatas ...[]byte) []byte {
	return Hmac(crypto.SHA256, data, secret, otherDatas...)
}

func Hmac(hmacHash crypto.Hash, data []byte, secret []byte, otherDatas ...[]byte) []byte {
	h := hmac.New(hmacHash.New, secret)
	h.Write(data)
	for _, other := range otherDatas {
		h.Write(other)
	}
	return h.Sum(nil)
}
