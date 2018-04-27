package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"crypto/md5"
	"crypto/sha1"
	"fmt"
)

func hmacMd5Hex(key []byte, data []byte) string {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	resBytes := mac.Sum(nil)
	return hex.EncodeToString(resBytes)
}

func hmacSha1Hex(key []byte, data []byte) string {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	resBytes := mac.Sum(nil)
	return hex.EncodeToString(resBytes)
}

func hmacSha256Hex(key []byte, data []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	resBytes := mac.Sum(nil)
	return hex.EncodeToString(resBytes)
}

func main() {
	key := []byte("xr6OnFq8XanLETxH")
	// utf8 default
	plainBytes := []byte("来自golang的问候")
	fmt.Println(hmacMd5Hex(key, plainBytes))
	fmt.Println(hmacSha1Hex(key, plainBytes))
	fmt.Println(hmacSha256Hex(key, plainBytes))
}
