package main


import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"encoding/hex"
)

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	unpadding := int(origData[length-1])

	if length - unpadding <= 0 || length - unpadding > length {
		return nil, errors.New("invalid padding")
	}

	return origData[:(length - unpadding)], nil
}

func AesEncryptCBCMode(origData, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, iv)
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func AesDecryptCBCMode(crypted, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	return PKCS7UnPadding(origData)
}

func main() {
	key := []byte("xr6OnFq8XanLETxH")
	iv := []byte("Pt1TnnURWIPnIFIA")

	plainBytes := []byte("测试AES加密PKCS7PADDING")
	encrypted, err := AesEncryptCBCMode(plainBytes, key, iv)
	if err != nil {
		panic(err)
	}

	encHex := hex.EncodeToString(encrypted)
	fmt.Printf("encrypted result in hex format: %s\n", encHex)

	encBytes, _ := hex.DecodeString(encHex)
	decrypted, err := AesDecryptCBCMode(encBytes, key, iv)
	if err != nil {
		panic(err)
	}
	fmt.Printf("decrypted result: %s\n", string(decrypted))
}
