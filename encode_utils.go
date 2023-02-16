package ecies

import (
	"encoding/hex"
)

func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

func HexDecode(dataInHex string) ([]byte, error) {
	data, err := hex.DecodeString(dataInHex)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func HexDecodeWithoutError(dataInHex string) []byte {
	data, err := hex.DecodeString(dataInHex)
	if err != nil {
		return nil
	}
	return data
}
