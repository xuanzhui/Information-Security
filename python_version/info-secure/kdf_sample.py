#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
refer https://docs.python.org/3/library/hashlib.html
Key derivation function: pbkdf2, bcrypt, scrypt
normally used to strengthen the password but slow and input length should be limited

pbkdf2:
Applications and libraries should limit password to a sensible length (e.g. 1024). 
Salt should be about 16 or more bytes from a proper source, e.g. os.urandom().
The number of iterations should be chosen based on the hash algorithm and computing power. As of 2013, at least 100,000 iterations of SHA-256 are suggested.
dklen is the length of the derived key. If dklen is None then the digest size of the hash algorithm hash_name is used, e.g. 64 for SHA-512.

bcrypt:
https://github.com/pyca/bcrypt

scrypt:
https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/?highlight=scrypt#cryptography.hazmat.primitives.kdf.scrypt.Scrypt
'''

import hashlib, binascii, bcrypt, math
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend


def pbkdf2_md5(password_bytes, salt, iterations, dklen=None):
	hash_bytes = hashlib.pbkdf2_hmac('md5', password_bytes, salt, iterations, dklen)
	return binascii.hexlify(hash_bytes).decode()


def pbkdf2_sha1(password_bytes, salt, iterations, dklen=None):
	hash_bytes = hashlib.pbkdf2_hmac('sha1', password_bytes, salt, iterations, dklen)
	return binascii.hexlify(hash_bytes).decode()


def pbkdf2_sha256(password_bytes, salt, iterations, dklen=None):
	hash_bytes = hashlib.pbkdf2_hmac('sha256', password_bytes, salt, iterations, dklen)
	return binascii.hexlify(hash_bytes).decode()


# bcrypt cost of 6 means 64 rounds (2**6 = 64)
# http://security.stackexchange.com/questions/17207/recommended-of-rounds-for-bcrypt
def bcrypt_freebsd_schema(password_bytes, cost):
	return bcrypt.hashpw(password_bytes, bcrypt.gensalt(cost, prefix=b'2a')).decode()


def bcrypt_freebsd_schema_verify(raw_password_bytes, bcrypt_password_bytes):
	return bcrypt.checkpw(raw_password_bytes, bcrypt_password_bytes)


# with help of cryptography library whose version will be 1.8+
def scrypt(password_bytes, salt, N, r, p, dklen):
	kdf = Scrypt(
		salt=salt,
		length=dklen,
		n=N,
		r=r,
		p=p,
		backend=default_backend()
	)
	hash_bytes = kdf.derive(password_bytes)
	return binascii.hexlify(hash_bytes).decode()


if __name__ == '__main__':
	key = 'imsS49kraapnUH0Z'.encode('utf-8')
	salt = b'pMlKhTre10obG1ep'
	print(pbkdf2_md5(key, salt, 1000, 16).upper())
	print(pbkdf2_sha1(key, salt, 1000, 20).upper())
	print(pbkdf2_sha256(key, salt, 1000, 32).upper())
	print(bcrypt_freebsd_schema(key, 6))
	print(scrypt(key, salt, 2**14, 8, 1, 64))
	print(bcrypt_freebsd_schema_verify(key, '$2a$06$k4UMa8i9sfoqr4OqH8XbSuN2xIHeEgzu.HKe8QK1V.nUSCAJjV38q'.encode('utf-8')))
