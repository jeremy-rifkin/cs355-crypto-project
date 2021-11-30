import os

RANDOM_NUMBER_BITS = 128
RANDOM_NUMBER_BYTES = RANDOM_NUMBER_BITS / 8

def generate_random(n_bytes):
    return os.urandom(n_bytes)

