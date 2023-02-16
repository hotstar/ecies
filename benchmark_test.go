package ecies

import (
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func Benchmark_P256_Message128_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P256(), 128)
}

func Benchmark_P256_Message128_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P256(), 128)
}

func Benchmark_P256_Message256_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P256(), 256)
}

func Benchmark_P256_Message256_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P256(), 256)
}

func Benchmark_P256_Message512_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P256(), 512)
}

func Benchmark_P256_Message512_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P256(), 512)
}

func Benchmark_P256_Message1024_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P256(), 1024)
}

func Benchmark_P256_Message1024_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P256(), 1024)
}

func Benchmark_P256_Message2048_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P256(), 2048)
}

func Benchmark_P256_Message2048_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P256(), 2048)
}

func Benchmark_P256_Message4096_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P256(), 4096)
}

func Benchmark_P256_Message4096_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P256(), 4096)
}

func Benchmark_P256_Message8192_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P256(), 8192)
}

func Benchmark_P256_Message8192_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P256(), 8192)
}

func Benchmark_P384_Message128_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P384(), 128)
}

func Benchmark_P384_Message128_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P384(), 128)
}

func Benchmark_P384_Message256_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P384(), 256)
}

func Benchmark_P384_Message256_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P384(), 256)
}

func Benchmark_P384_Message512_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P384(), 512)
}

func Benchmark_P384_Message512_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P384(), 512)
}

func Benchmark_P384_Message1024_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P384(), 1024)
}

func Benchmark_P384_Message1024_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P384(), 1024)
}

func Benchmark_P384_Message2048_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P384(), 2048)
}

func Benchmark_P384_Message2048_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P384(), 2048)
}

func Benchmark_P384_Message4096_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P384(), 4096)
}

func Benchmark_P384_Message4096_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P384(), 4096)
}

func Benchmark_P384_Message8192_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P384(), 8192)
}

func Benchmark_P384_Message8192_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P384(), 8192)
}

func Benchmark_P521_Message128_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P521(), 128)
}

func Benchmark_P521_Message128_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P521(), 128)
}

func Benchmark_P521_Message256_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P521(), 256)
}

func Benchmark_P521_Message256_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P521(), 256)
}

func Benchmark_P521_Message512_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P521(), 512)
}

func Benchmark_P521_Message512_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P521(), 512)
}

func Benchmark_P521_Message1024_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P521(), 1024)
}

func Benchmark_P521_Message1024_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P521(), 1024)
}

func Benchmark_P521_Message2048_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P521(), 2048)
}

func Benchmark_P521_Message2048_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P521(), 2048)
}

func Benchmark_P521_Message4096_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P521(), 4096)
}

func Benchmark_P521_Message4096_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P521(), 4096)
}

func Benchmark_P521_Message8192_Encryption(b *testing.B) {
	benchmarkEncryption(b, elliptic.P521(), 8192)
}

func Benchmark_P521_Message8192_Decryption(b *testing.B) {
	benchmarkDecryption(b, elliptic.P521(), 8192)
}

func Benchmark_RSA3072_Message128_Encryption(b *testing.B) {
	b.StopTimer()
	msg := randomBytes(128)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	publicKey := privateKey.PublicKey
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		rsaEncryption(msg, publicKey)
	}
}

func Benchmark_RSA3072_Message128_Decryption(b *testing.B) {
	b.StopTimer()
	msg := randomBytes(128)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	publicKey := privateKey.PublicKey
	encMsg := rsaEncryption(msg, publicKey)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		rsaDecrypt(encMsg, *privateKey)
	}
}

func Benchmark_RSA3072_Message256_Encryption(b *testing.B) {
	b.StopTimer()
	msg := randomBytes(256)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	publicKey := privateKey.PublicKey
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		rsaEncryption(msg, publicKey)
	}
}

func Benchmark_RSA3072_Message256_Decryption(b *testing.B) {
	b.StopTimer()
	msg := randomBytes(256)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 3072)
	publicKey := privateKey.PublicKey
	encMsg := rsaEncryption(msg, publicKey)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		rsaDecrypt(encMsg, *privateKey)
	}
}

func rsaEncryption(msg []byte, key rsa.PublicKey) []byte {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, _ := rsa.EncryptOAEP(sha256.New(), rng, &key, msg, label)
	return ciphertext
}

func rsaDecrypt(encryptedMsg []byte, privKey rsa.PrivateKey) []byte {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	message, _ := rsa.DecryptOAEP(sha256.New(), rng, &privKey, encryptedMsg, label)
	return message
}

func benchmarkEncryption(b *testing.B, curve elliptic.Curve, l int) {
	b.StopTimer()
	message := generateMessage(b, l)

	SetCurve(curve)
	k, err := GenerateKey()
	assert.Nil(b, err)
	ecies := NewECIES()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ecies.Encrypt(k.PublicKey, message)
	}
	ClearCurve()
}

func benchmarkDecryption(b *testing.B, curve elliptic.Curve, l int) {
	b.StopTimer()
	message := generateMessage(b, l)

	SetCurve(curve)
	k, err := GenerateKey()
	assert.Nil(b, err)
	ecies := NewECIES()
	encMessage, err := ecies.Encrypt(k.PublicKey, message)
	assert.Nil(b, err)
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		ecies.Decrypt(k, encMessage)
	}
	ClearCurve()
}

func generateMessage(b *testing.B, len int) []byte {
	message := make([]byte, len)
	l, err := io.ReadFull(rand.Reader, message)
	assert.Equal(b, len, l)
	assert.Nil(b, err)
	return message
}
