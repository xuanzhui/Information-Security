package main

import (
	"crypto/md5"
	"encoding/hex"
	"crypto/sha256"
	"crypto/sha1"
	"fmt"
)

func md5Hex(data []byte) string {
	h := md5.New()
	h.Write(data)
	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func sha1Hex(data []byte) string {
	h := sha1.New()
	h.Write(data)
	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes)
}


func sha256Hex(data []byte) string {
	h := sha256.New()
	h.Write(data)
	hashBytes := h.Sum(nil)
	return hex.EncodeToString(hashBytes)
}

func main() {
	// utf8 default
	plainBytes := []byte("来自golang的问候")
	fmt.Println(md5Hex(plainBytes))
	fmt.Println(sha1Hex(plainBytes))
	fmt.Println(sha256Hex(plainBytes))
}
