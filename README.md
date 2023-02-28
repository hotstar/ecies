# Introduction

This package is an implementation of the Elliptic Curve Integrated Encryption Scheme (ECIES), following the specification recommended in [Victor Shoup's paper](https://www.shoup.net/papers/iso-2_1.pdf). We refer to this implementation as the "Shoup's version" of ECIES.

We noticed that while Botan and Bouncy Castle have implemented the Shoup's version of ECIES, we could not find a Golang package that implemented it. As a result, interactions of ECIES-encrypted data among ecosystems coded in different languages can be difficult. To address this, the Disney+Hotstar Security Team implemented the Shoup's version of ECIES in Golang and is contributing it back to the community.

According to the [wiki](https://www.cryptopp.com/wiki/Elliptic_Curve_Integrated_Encryption_Scheme), our implementation is compatible with the Botan and Bouncy Castle implementations.


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
implementations. We can use this method ```ecies.NewCustomizedECIES``` to use our own component. We can also switch
to different curve by set the variable ```CURVE```

Also, we provide a default implementation using this method ```ecies.NewECIES``` , the following is the details.

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

#### Compatibility

So far, we have verified the compatibility with C++ Botan and Java BouncyCastle. Let's take the BouncyCastle as an example. 

+ BouncyCastle

```xml
<dependency>
   <groupId>org.bouncycastle</groupId>
   <artifactId>bcpkix-jdk18on</artifactId>
   <version>1.71</version>
</dependency>
```

```java

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.IESEngine;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.util.DigestFactory;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

public class BouncyCastleECIES {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final String EC_ALGORITHM_NAME = "EC";
    private static final String CURVE = "secp256r1";

    private static final IESParameterSpec IES_PARAMETER_SPEC_FOR_AES_CBC =
        new IESParameterSpec(null, null, 128, 128, null);

    public static byte[] encrypt(byte[] plainText, BCECPublicKey publicKey) throws Exception {
        IESCipher cipher = getIESCipher();
        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, IES_PARAMETER_SPEC_FOR_AES_CBC, new SecureRandom());
        return cipher.engineDoFinal(plainText, 0, plainText.length);
    }

    public static byte[] decrypt(byte[] cipherText, BCECPrivateKey privateKey) throws Exception {
        IESCipher cipher = getIESCipher();
        cipher.engineInit(Cipher.DECRYPT_MODE, privateKey, IES_PARAMETER_SPEC_FOR_AES_CBC, new SecureRandom());
        return cipher.engineDoFinal(cipherText, 0, cipherText.length);
    }


    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGenerator =
            KeyPairGenerator.getInstance(EC_ALGORITHM_NAME, BouncyCastleProvider.PROVIDER_NAME);
        keyGenerator.initialize(new ECGenParameterSpec(CURVE));
        KeyPair keyPair = keyGenerator.generateKeyPair();
        return keyPair;
    }

    public static String serializePrivateKey(BCECPrivateKey privateKey) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(privateKey.getD());
        return Hex.toHexString(bytes);
    }

    public static String serializePublicKey(BCECPublicKey publicKey) throws Exception {
        byte[] bytes = publicKey.getQ().getEncoded(false);
        return Hex.toHexString(bytes);
    }

    private static IESCipher getIESCipher() {
        IESCipher cipher = new IESCipher(
            new IESEngine(
                new ECDHBasicAgreement(),
                new KDF2BytesGenerator(new SHA256Digest()),
                new HMac(DigestFactory.createSHA256()),
                new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding())), 0);
        return cipher;
    }

    // we can test the compatibility using the output data
    public static void main(String[] args) throws Exception {
        String msg="hello_ECIES";
        KeyPair keyPair = generateKeyPair();
        BCECPublicKey publicKey = (BCECPublicKey) keyPair.getPublic();
        BCECPrivateKey privateKey = (BCECPrivateKey) keyPair.getPrivate();
        System.out.println("privateKeyString: "+serializePrivateKey(privateKey));
        System.out.println("publicKeyString: "+serializePublicKey(publicKey));
        byte[] encData = encrypt(msg.getBytes(), publicKey);
        System.out.println("encMessage: "+Hex.toHexString(encData));
        byte[] plainData = decrypt(encData, privateKey);
        System.out.println(new String(plainData));
    }
}
```

By the code above, we output the privateKeyString and the encMessage. We can decrypt using the Go implementation below.

```go
package main

import (
	"fmt"
	"github.com/hotstar/ecies"
)

func main() {
	privateKeyString := "" 
	encMessage := ""

	privateKey := ecies.DeserializePrivateKey(ecies.HexDecodeWithoutError(privateKeyString))
	cipher := ecies.NewECIES()
	palinMessage, _ := cipher.Decrypt(privateKey, ecies.HexDecodeWithoutError(encMessage))
	fmt.Println(string(palinMessage))
}

```