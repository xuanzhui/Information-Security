#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
'''

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding

def private_key_from_pem(pem_path):
	with open(pem_path, "rb") as key_file:
		private_key = serialization.load_pem_private_key(
			key_file.read(),
			password=None,
			backend=default_backend()
		)

	return private_key


def public_key_from_pem(pem_path):
	with open(pem_path, "rb") as key_file:
		public_key = serialization.load_pem_public_key(
			key_file.read(),
			backend=default_backend()
		)

	return public_key


def encrypt_with_OAEP(public_key, plain_bytes):
	cipher_bytes = public_key.encrypt(
		plain_bytes,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	return cipher_bytes


def decrypt_with_OAEP(private_key, cipher_bytes):
	plain_bytes = private_key.decrypt(
		cipher_bytes,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	return plain_bytes


def sign_with_PSS(private_key, plain_bytes, salt_len):
	return private_key.sign(
		plain_bytes,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=salt_len
		),
		hashes.SHA256()
	)


# If the signature does not match, raise an InvalidSignature exception.
def verify_with_PSS(public_key, sign_bytes, plain_bytes, salt_len):
	public_key.verify(
		sign_bytes,
		plain_bytes,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=salt_len
		),
		hashes.SHA256()
	)


if __name__ == '__main__':
	CERT_BASE_PATH = '../../cipher_keys/'
	PRIVATE_KEY_PATH = CERT_BASE_PATH + 'pkcs8_rsa_private_key_2048.pem'
	PUBLIC_KEY_PATH = CERT_BASE_PATH + 'rsa_public_key_2048.pem'

	import binascii

	private_key = private_key_from_pem(PRIVATE_KEY_PATH)
	public_key = public_key_from_pem(PUBLIC_KEY_PATH)
	plain_text = '测试RSA算法--RSA/ECB/OAEPWithSHA'

	cipher_txt = b'0C537DA699CE778E21AAC347A0F528C0584C059C2AD24C27FF6DC39603EDAE87015F596E0CE3440729CD529E9B4ECA8C4EBA577D6A3A5CEB645F7253AA3B68AA205490B973A067614CD17EB7E7DDB81482BED0FAD4E536D9544A18247D628348419AC9D2C9206730682B551E7DB7D1572ED4D384F1CD840C55DAE2DAB0479960931ED526748B87527A3AA1D56772A327AB508A9CE956FB6ACB0A0ACA5DF9A2FC3B25A0154933F65B1965F0313324FC5DBA7B3F7BE7033AF343ACE10B16156786FF1EC18FFB4A5881220F54E2E5EEBE76FBAB20E9EA6CC09883E4CEA7ECA5040C2FB5A58B7E80D5CA624C353C1ADE142B5E70CF99FC112554BFD78CBD9C21923C'
	cipher_bytes = binascii.unhexlify(cipher_txt)
	plain_bytes = decrypt_with_OAEP(private_key, cipher_bytes)
	print(plain_bytes.decode('utf-8'))

	cipher_bytes = encrypt_with_OAEP(public_key, plain_text.encode('utf-8'))
	print(binascii.hexlify(cipher_bytes).decode().upper())

	sign_bytes = sign_with_PSS(private_key, plain_text.encode(), 20)
	print(binascii.hexlify(sign_bytes).decode().upper())

	sign_hex = b'12517AA7F5FA15377B1A26997EA352D9E2A3A11CEF70095D0728129E3CC034CE9FE92B7819DE340001638D2C85D4D2C7CD0CB99FE4E7F78F274AF21DC8EF6AA3D284524817767ACDF26FB3B8BA311DCDA927147606D38A0B4FF8A78B516B0A96D1D8C8FD886CC7545449EEFF3E821A6A0C11AB905CAA3F3AAFB3E5D63BDFC92DFB9E359C6D4CE384EE3EEC2EAC87FFB1228CC3A9AB7B2CF9D8B57FFE35D1A8C2914010731E312EA135747B0C25D207D76CF4327B5A22F86A0E2787CE23FDAF9369EC34EDA0E7D763B1024DE8A58DDEE48ACC1C9333B5D79A49F534A18ED555861F7529A9D31119C1DB473DF431D7D16A931465635D412C832ECFF3D543F4D47B'
	sign_bytes = binascii.unhexlify(sign_hex)
	verify_with_PSS(public_key, sign_bytes, plain_text.encode(), 20)
