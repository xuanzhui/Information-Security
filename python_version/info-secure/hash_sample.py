#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
refer https://docs.python.org/3/library/hashlib.html
normally hash result will be represented by hex string to compare
'''

import hashlib

def md5(plain_bytes):
	return hashlib.md5(plain_bytes).hexdigest()


def sha1(plain_bytes):
	return hashlib.sha1(plain_bytes).hexdigest()


def sha256(plain_bytes):
	return hashlib.sha256(plain_bytes).hexdigest()


if __name__ == '__main__':
	plain_bytes = '来自python的问候'.encode('utf-8')
	print(md5(plain_bytes).upper())
	print(sha1(plain_bytes).upper())
	print(sha256(plain_bytes).upper())

	# with open('D:/迅雷下载/kali-linux-2017.2-amd64/kali-linux-2017.2-amd64.iso', 'rb') as file:
	# 	print(sha256(file.read()))
