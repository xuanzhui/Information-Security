package main

import (
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"crypto/sha256"
	"crypto"
	"io/ioutil"
	"fmt"
	"encoding/hex"
)

// normally bits length 1024 2048
// first return is private key in pkcs8 format
// second return is public key in PKIX format
func GenRsaKeyPairAsPemStr(bits int) (string, string, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)

	if err != nil {
		return "", "", err
	}

	publicKey := &privateKey.PublicKey

	priBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", err
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}

	priKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: priBytes,
		},
	)

	pubKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		},
	)
	return string(priKeyPem), string(pubKeyPem), nil
}

func ParsePKCS8PemPrivateKey(pemStr string) (*rsa.PrivateKey, error)  {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("failed to decode PEM format key")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if ok {
		return rsaKey, nil
	} else {
		return nil, errors.New("invalid key type")
	}
}

func ParsePKIXPemPublicKey(pubPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return nil, errors.New("failed to decode PEM format key")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if ok {
		return rsaKey, nil
	} else {
		return nil, errors.New("invalid key type")
	}
}

func RsaEncryptWithOAEP(pubKey *rsa.PublicKey, plain []byte) ([]byte, error) {
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, plain, []byte(""))
}

func RsaDecryptWithOAEP(priKey *rsa.PrivateKey, cipher []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priKey, cipher, []byte(""))
}

func RsaSignWithPSS(priKey *rsa.PrivateKey, plain []byte, saltLen int) ([]byte, error) {
	pssOption := rsa.PSSOptions{}
	pssOption.SaltLength = saltLen
	pssOption.Hash = crypto.SHA256

	shOp := crypto.SHA256.New()
	shOp.Write(plain)
	hashed := shOp.Sum(nil)

	return rsa.SignPSS(rand.Reader, priKey, crypto.SHA256, hashed, &pssOption)
}

// if error is nil sign is good
func RsaVerifyWithPSS(pubKey *rsa.PublicKey, plain []byte, signed []byte, saltLen int) error {
	pssOption := rsa.PSSOptions{}
	pssOption.SaltLength = saltLen
	pssOption.Hash = crypto.SHA256

	shOp := crypto.SHA256.New()
	shOp.Write(plain)
	hashed := shOp.Sum(nil)

	return rsa.VerifyPSS(pubKey, crypto.SHA256, hashed, signed, &pssOption)
}

func main() {
	dirPath := "../../cipher_keys/"
	privateKeyPath := dirPath + "pkcs8_rsa_private_key_2048.pem"
	pubKeyPath := dirPath + "rsa_public_key_2048.pem"

	priPemBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		panic(err)
	}
	priPem := string(priPemBytes)

	pubPemBytes, err := ioutil.ReadFile(pubKeyPath)
	if err != nil {
		panic(err)
	}
	pubPem := string(pubPemBytes)

	priKey, err := ParsePKCS8PemPrivateKey(priPem)
	if err != nil {
		panic(err)
	}

	pubKey, err := ParsePKIXPemPublicKey(pubPem)
	if err != nil {
		panic(err)
	}

	cipherBytes, err := RsaEncryptWithOAEP(pubKey, []byte("测试RSA算法--RSA/ECB/OAEPWithSHA"))
	if err != nil {
		panic(err)
	}
	fmt.Printf("encrypted result in hex format: %s\n", hex.EncodeToString(cipherBytes))

	plainBytes, err := RsaDecryptWithOAEP(priKey, cipherBytes)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted result: %s\n", string(plainBytes))

	signedBytes, err := RsaSignWithPSS(priKey, []byte("测试RSA算法--RSA/ECB/OAEPWithSHA"), 20)
	fmt.Printf("signed result in hex format: %s\n", hex.EncodeToString(signedBytes))

	err1 := RsaVerifyWithPSS(pubKey, []byte("测试RSA算法--RSA/ECB/OAEPWithSHA"), signedBytes, 20)
	if err1 != nil {
		fmt.Println("invalid sign")
	}
}
