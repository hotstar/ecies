package ecies

import "crypto/elliptic"

var (
	defaultCurve = elliptic.P256()
	curve        = defaultCurve
)

func GetCurve() elliptic.Curve {
	return curve
}

// GetECPointByteLength Get the length of bytes of a point on the curve
func GetECPointByteLength() int {
	byteLen := (curve.Params().BitSize + 7) / 8
	return 1 + 2*byteLen
}

// SetCurve set your own elliptic curve
func SetCurve(c elliptic.Curve) {
	curve = c
}

// ClearCurve clear your own elliptic curve, instead the default curve
func ClearCurve() {
	curve = defaultCurve
}
