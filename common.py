import os
import re

RANDOM_NUMBER_BITS = 128
RANDOM_NUMBER_BYTES = RANDOM_NUMBER_BITS / 8

def generate_random(n_bytes):
    return os.urandom(n_bytes)

SERVER_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)")

def parse_server(str):
    m = SERVER_RE.match(str)
    if m:
        return(m.groups())
    else:
        raise ValueError("Invalid server specification, must be ip:port")
