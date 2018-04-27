#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/

CBC (Cipher Block Chaining) is a mode of operation for block ciphers. It is considered cryptographically strong.
ECB is considered insecure now.
always change key and vector before encryption in production environment
'''

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import binascii


def encrypt_cbc_mode(key, iv, plain_bytes):
	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	# add pkcs#7 padding before encrypt
	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(plain_bytes) + padder.finalize()
	return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_cbc_mode(key, iv, cipher_bytes):
	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	decryptor = cipher.decryptor()
	content = decryptor.update(cipher_bytes) + decryptor.finalize()
	# unpad after decrypt
	unpadder = padding.PKCS7(128).unpadder()
	return unpadder.update(content) + unpadder.finalize()


def encrypt_ecb_mode(key, plain_bytes):
	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
	encryptor = cipher.encryptor()
	padder = padding.PKCS7(128).padder()
	padded_data = padder.update(plain_bytes) + padder.finalize()
	return encryptor.update(padded_data) + encryptor.finalize()


def decrypt_ecb_mode(key, cipher_bytes):
	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
	decryptor = cipher.decryptor()
	content = decryptor.update(cipher_bytes) + decryptor.finalize()
	unpadder = padding.PKCS7(128).unpadder()
	return unpadder.update(content) + unpadder.finalize()


if __name__ == '__main__':
	key = b'xr6OnFq8XanLETxH'
	iv = b'Pt1TnnURWIPnIFIA'
	plain_bytes = '测试AES加密PKCS7PADDING'.encode('utf-8')

	encrypt_data = encrypt_cbc_mode(key, iv, plain_bytes)
	print(binascii.hexlify(encrypt_data).decode().upper())

	plain_bytes = decrypt_cbc_mode(key, iv, encrypt_data)
	print(plain_bytes.decode('utf-8'))

	encrypt_data = encrypt_ecb_mode(key, plain_bytes)
	print(binascii.hexlify(encrypt_data).decode().upper())

	plain_bytes = decrypt_ecb_mode(key, encrypt_data)
	print(plain_bytes.decode('utf-8'))
