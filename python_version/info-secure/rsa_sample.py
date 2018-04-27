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
	CERT_BASE_PATH = 'C:/Users/xuanzhui/WorkSpace/own/Information-Security/cipher_keys/'
	PRIVATE_KEY_PATH = CERT_BASE_PATH + 'pkcs8_rsa_private_key_2048.pem'
	PUBLIC_KEY_PATH = CERT_BASE_PATH + 'rsa_public_key_2048.pem'

	import binascii

	private_key = private_key_from_pem(PRIVATE_KEY_PATH)
	public_key = public_key_from_pem(PUBLIC_KEY_PATH)
	plain_text = 'JAVA测试RSA算法--RSA/ECB/OAEPWithSHA'

	cipher_txt = b'256FCD333784E40A0EEDCEAC64EBBA106E5C0183F53C98708D000788562B3E05066BAE561D1D4C3D2A1D709B0553AF9BF244A84B4BB7595BC734B196C59B53AFD531535A56842E08673CFBBEA7F798EE4EF079E3296D1F7027A48F46DD347AD18243DB801DE42E4A6247963A1043D50F3B8EC6DDA003C535B37F8FF4F5F48196D191509AEDC8425336AA113F779B8D06CA1FD3C10BEF723EC5A759C25CCC59A26ADD81BBBD44A23942B241BC3B98896D7B7C37632DF12B1F2FB6CB0E8B380F5FFF4691BDF9A9A9362581A48970208A1C5DFAB22C995D640D68F26B7056E85A4EEBC054B682C07B9983AD671CFB696BF9E20758BF1076EE915842DCAD6D73C090'
	cipher_bytes = binascii.unhexlify(cipher_txt)
	plain_bytes = decrypt_with_OAEP(private_key, cipher_bytes)
	print(plain_bytes.decode('utf-8'))

	cipher_bytes = encrypt_with_OAEP(public_key, plain_text.encode('utf-8'))
	print(binascii.hexlify(cipher_bytes).decode().upper())

	sign_bytes = sign_with_PSS(private_key, plain_text.encode(), 20)
	print(binascii.hexlify(sign_bytes).decode().upper())

	sign_hex = b'324FBDD3FD5DDFFDA78B773EB423561D22D8FE9EEB8822DCE33B4FFA06632ADBAD02190B2FE05A30B03E6FA5E90C0FCF750DC2B42BA1D67D20D9AEF4A3DF1B3C342D68CED4C7CE5E53302B50454CD4BA050BAF76F6015814AA65FE718309BFBC58F8D7220F9C3DA21CA696ACCCA0C4D189EBD91B21CE75899FF8D9CC79CEC4704D5E88A065219630EA7492C7966F65ACB77BEA57C19774A4B0BFAC4CC291BAD5337DFC5CC28B9EA813C25D31585B94D2C1C158738A6DD176CC09318509A08E2DB5EEB70753BD9220B53D021005BD1269FC6EA8094B1E248C933F7C65F69C7F1D620F9A8C8897D1BA29D8F5972144E561C8E06205C79FB4F9F5380D74760E4E12'
	sign_bytes = binascii.unhexlify(sign_hex)
	verify_with_PSS(public_key, sign_bytes, plain_text.encode(), 20)
