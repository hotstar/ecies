# Background

Botan and Bouncy Castle implemented Shoup's version of ECIES, but we Hotstar Security Team found that it was hard to find an 
implementation of the Shoup's version of ECIES in Golang package, which results that the interactions of ECIES encrypted data 
among ecosystems coding in different languages are difficult. Therefore, we implemented one and give it back to the community.

# Introduction

This package is an implementation of Elliptic Curve Integrated Encryption Scheme (ECIES).
It follows the specification recommended in the [paper](https://www.shoup.net/papers/iso-2_1.pdf) from Victor Shoup.
We call it the Shoup's version of ECIES.

Referring to the [wiki](https://www.cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme), the Botan and Bouncy Castle
implemented Shoup's version of ECIES, so our implementation is compatible with them.

#### The encryption flow is as follows:

1. The sender generates an ephemeral key pair (ephemeral public key and ephemeral private key)
2. The sender calculates a shared secret using the Key Agreement, getting ephemeral private key and receiver's
public key as the input parameters
3. The sender derives keys using the Key Derivation Function, getting the shared secret as the input parameters
4. The sender retrieves two keys from the derived keys, one is for encryption and the other is for mac
5. The sender calculates cipher message using the Symmetric Cipher, getting the plain message and encryption key 
as the input parameters.
6. The sender calculates mac, getting the cipher message and mac key as the input parameters
7. The sender sends the ephemeral public key, the cipher message, and the mac to the receiver.

#### The decryption flow is as follows:

1. The receiver retrieves the ephemeral public key
2. The receiver calculates a shared secret using the Key Agreement, getting ephemeral public key and its own 
   private key as the input parameters 
3. The receiver derives keys using the Key Derivation Function, getting the shared secret as the input parameters
4. The receiver retrieves two keys from the derived keys, one is for encryption and the other is for mac
5. The receiver validates the mac, getting the cipher message and mac key as the input parameters
6. The receiver calculates the plain message using the Symmetric Cipher, getting the cipher message and encryption key
   as the input parameters.

# Quick Start

```go

import (
	"fmt"
)

func example1() {
	k, err := GenerateKey()
	if err != nil {
		panic("failed to generate key pair")
	}
	privateKey := k
	publicKey := k.PublicKey

	serializedPrivateKey := HexEncode(SerializePrivateKey(privateKey))
	serializedPublicKey := HexEncode(SerializePublicKey(publicKey))
	fmt.Println("privateKey=" + serializedPrivateKey)
	fmt.Println("publicKey=" + serializedPublicKey)

	deserializedPrivateKey := DeserializePrivateKey(HexDecodeWithoutError(serializedPrivateKey))
	deserializedPublicKey, err := DeserializePublicKey(HexDecodeWithoutError(serializedPublicKey))
	if err != nil {
		panic("failed to deserialize key pair")
	}
	fmt.Println(deserializedPrivateKey.D.Cmp(privateKey.D) == 0)
	fmt.Println(deserializedPublicKey.X.Cmp(publicKey.X) == 0)
	fmt.Println(deserializedPublicKey.Y.Cmp(publicKey.Y) == 0)

	ecies := NewECIES()
	plainText := "hello world"
	encryptedTextBytes, err := ecies.Encrypt(publicKey, []byte(plainText))
	if err != nil {
		panic("failed to encrypt message")
	}
	decryptedTextBytes, err := ecies.Decrypt(privateKey, encryptedTextBytes)
	if err != nil {
		panic("failed to decrypt message")
	}
	fmt.Println(string(decryptedTextBytes))

}

```

# Usage

There are four key parts in the ECIES. They are Key Agreement, Key Derivation Function, Symmetric Cipher, and
MAC. In our implementation, we provide interface for each of them so that developers can have their own 
implementations. We can use this method ```shoupecies.NewCustom()``` to use our own component. We can also switch
to different curve by set the variable ```CURVE```

Also, we provide a default implementation using this method ```shoupecies.New``` , the following is the details.

| Part                    | Spec                 | Comment                             |
|-------------------------|----------------------|-------------------------------------|
| Elliptic Curve          | secp256r1            | Also known as P256 or prime256v1.   |
| Key Agreement           | ECDHBasicAgreement   | P1363 7.2.1 ECSVDP-DH               |
| Key Derivation Function | KDF2 with SHA256     | IEEE P1363 or ISO 18033             |
| MAC                     | HmacSHA256           |                                     |
| Symmetric Cipher        | AES-CBC-PKCS7Padding |                                     |

 # Benchmark

In this part, we are giving some benchmarks for different elliptic curves, they are `P256`、`P384` and `P521`.
Refer to [here](https://pkg.go.dev/crypto/elliptic) to get more details about these curves.

#### Test Machine configuration:
  + CPU: Apple M1 Pro
  + Memory: 16 GB
  + OS: macOS Ventura 13.0.1

#### Benchmark Results
  + `P256` is also known as `secp256r1`, the benchmark of which is as below.

| Message Length (Byte) | Encryption Time (ns/op) | Decryption Time (ns/op) |
|-----------------------|-------------------------|-------------------------|
| 128                   | 57043                   | 44975                   |
| 256                   | 57432                   | 45092                   |
| 512                   | 56926                   | 44992                   |
| 1024                  | 59012                   | 45314                   |
| 2048                  | 59083                   | 46418                   |
| 4096                  | 62557                   | 48598                   |
| 8192                  | 69278                   | 52830                   |

+ `P384` is also known as `secp384r1`, the benchmark of which is as below.

| Message Length (Byte) | Encryption Time (ns/op) | Decryption Time (ns/op) |
|-----------------------|-------------------------|-------------------------|
| 128                   | 998769                  | 500437                  |
| 256                   | 1005223                 | 502177                  |
| 512                   | 1012345                 | 498896                  |
| 1024                  | 1007236                 | 498630                  |
| 2048                  | 1020338                 | 508600                  |
| 4096                  | 1014529                 | 509956                  |
| 8192                  | 1034656                 | 521036                  |


+ `P521` is also known as `secp521r1`, the benchmark of which is as below.

| Message Length (Byte) | Encryption Time (ns/op) | Decryption Time (ns/op) |
|-----------------------|-------------------------|-------------------------|
| 128                   | 3101959                 | 1507083                 |
| 256                   | 3042652                 | 1529502                 |
| 512                   | 3075750                 | 1550932                 |
| 1024                  | 3140785                 | 1545537                 |
| 2048                  | 3146527                 | 1584484                 |
| 4096                  | 3130114                 | 1565796                 |
| 8192                  | 3163863                 | 1561788                 |

+ For comparing with P256, we gave the benchmark of RSA3072 (RSA3072 has the same security level as P256).
 
| Message Length (Byte) | Encryption Time (ns/op) | Decryption Time (ns/op) |
|-----------------------|-------------------------|-------------------------|
| 128                   | 71317                   | 2747494                 |
| 256                   | 90165                   | 3709487                 |

