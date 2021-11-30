#!/usr/bin/python3

from cryptography.hazmat.primitives import hashes

# create test file with dd if=/dev/urandom of=password_file bs=4096 count=976562

digest = hashes.Hash(hashes.SHA3_256())

with open("password_file", "rb") as f:
	while True:
		block = f.read(4096 * 16)
		if not block:
			break
		digest.update(block)

print(digest.finalize().hex())
