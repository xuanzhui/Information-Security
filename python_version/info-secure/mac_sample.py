#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
refer https://docs.python.org/3.6/library/hmac.html
normally hash result will be represented by hex string to compare
'''


import hashlib, hmac

def hmac_md5(plain_bytes, key):
	mac_op = hmac.new(key, digestmod=hashlib.md5)
	mac_op.update(plain_bytes)
	return mac_op.hexdigest()


def hmac_sha1(plain_bytes, key):
	mac_op = hmac.new(key, digestmod=hashlib.sha1)
	mac_op.update(plain_bytes)
	return mac_op.hexdigest()


def hmac_sha256(plain_bytes, key):
	mac_op = hmac.new(key, digestmod=hashlib.sha256)
	mac_op.update(plain_bytes)
	return mac_op.hexdigest()


if __name__ == '__main__':
	plain_bytes = '来自python的问候'.encode('utf-8')
	key = b'imsS49kraapnUH0Z'

	print(hmac_md5(plain_bytes, key).upper())
	print(hmac_sha1(plain_bytes, key).upper())
	print(hmac_sha256(plain_bytes, key).upper())
