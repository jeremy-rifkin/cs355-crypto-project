import os
import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidSignature

RANDOM_NUMBER_BITS = 128
RANDOM_NUMBER_BYTES = RANDOM_NUMBER_BITS // 8
KEY_SIZE_BITS = 256
KEY_SIZE_BYTES = KEY_SIZE_BITS // 8

# The longest message ever sent is {m1, m2, n1 ⊕ n2, P2_name, HMAC_k({m1, m2, n1 ⊕ n2, P2_name})}
# Gives us a limit for name length, don't want to have to deal with messages longer than 1024 for now
MAX_NAME_LENGTH = (1024 - (RANDOM_NUMBER_BITS * 3 + KEY_SIZE_BITS)) // 8 # includes null terminator

def generate_random(n_bytes: int):
    return os.urandom(n_bytes)

SERVER_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+|localhost):(\d+)")

def parse_server(str: int):
    m = SERVER_RE.match(str)
    if m:
        return (m.group(1), int(m.group(2)))
    else:
        raise ValueError("Invalid server specification, must be ip:port")

def sha3_file(path: str):
    assert hashes.SHA3_256.digest_size == KEY_SIZE_BYTES
    sha3 = hashes.Hash(hashes.SHA3_256())
    with open(path, "rb") as f:
        while True:
            block = f.read(4096 * 16)
            if not block:
                break
            sha3.update(block)
    return sha3.finalize()

def authenticate(message: bytes, key: bytes):
    assert len(key) == KEY_SIZE_BYTES
    assert hashes.SHA3_256.digest_size == KEY_SIZE_BYTES
    h = HMAC(key, hashes.SHA3_256())
    h.update(message)
    return message + h.finalize()

def verify(full_message: bytes, key: bytes):
    mac = full_message[-KEY_SIZE_BYTES:]
    msg = full_message[:len(full_message) - KEY_SIZE_BYTES]
    h = HMAC(key, hashes.SHA3_256())
    h.update(msg)
    try:
        h.verify(mac)
    except InvalidSignature:
        return False
    else:
        return True

def xor_bytes(b1: bytes, b2: bytes):
    assert len(b1) == len(b2)
    b1_num = int.from_bytes(b1, byteorder="big", signed=False)
    b2_num = int.from_bytes(b2, byteorder="big", signed=False)
    xor = b1_num ^ b2_num
    return xor.to_bytes(len(b1), "big", signed=False)

def parse_message(step_num: int, msg: bytes):
    # Three types of messages sent in three different steps
    # 2. {n1, n2, P1_name, HMAC_k({n1, n2, P1_name})}
    # 4. {m1, m2, n1 ⊕ n2, P2_name, HMAC_k({m1, m2, n1 ⊕ n2, P2_name})}
    # 6. {m1 ⊕ m2, P1_name, HMAC_k({m1 ⊕ m2, P1_name})}
    if step_num == 2:
        n1 =   msg[0:RANDOM_NUMBER_BYTES]
        n2 =   msg[RANDOM_NUMBER_BYTES:2*RANDOM_NUMBER_BYTES]
        name = msg[2*RANDOM_NUMBER_BYTES:len(msg) - KEY_SIZE_BYTES]
        #mac  = msg[len(msg) - KEY_SIZE_BYTES:]
        return (n1, n2, name)
    elif step_num == 4:
        m1 =   msg[0:RANDOM_NUMBER_BYTES]
        m2 =   msg[RANDOM_NUMBER_BYTES:2*RANDOM_NUMBER_BYTES]
        xor =  msg[2*RANDOM_NUMBER_BYTES:3*RANDOM_NUMBER_BYTES]
        name = msg[3*RANDOM_NUMBER_BYTES:len(msg) - KEY_SIZE_BYTES]
        #mac  = msg[len(msg) - KEY_SIZE_BYTES:]
        return (m1, m2, xor, name)
    elif step_num == 6:
        xor =  msg[0:RANDOM_NUMBER_BYTES]
        name = msg[RANDOM_NUMBER_BYTES:len(msg) - KEY_SIZE_BYTES]
        #mac  = msg[len(msg) - KEY_SIZE_BYTES:]
        return (xor, name)
    else:
        assert False

class VerificationFailure(Exception):
    pass
