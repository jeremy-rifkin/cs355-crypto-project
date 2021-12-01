#!/usr/bin/python3
# Server for exchange. Sets up communication method.

import socket
import sys
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA3_256

from common import KEY_SIZE_BITS, MAX_NAME_LENGTH, RANDOM_NUMBER_BYTES, authenticate, generate_random, parse_server, sha3_file, verify, xor_bytes

def help():
    print("usage: ./client.py password_file client_name target_ip:port target_name")

secret_key = None

# Round 1 (Client): Client sends n1 || n2 || P1_Name || MAC(n1, n2, P1_Name)
# Round 1 (Server): Server sends m1 || m2 || n1 XOR n2 || P2_Name || MAC(m1, m2, n1^n2, P2_Name)
# Round 2 (Client): Check validity of signature. Send m1^m2 || P1_Name || MAC(m1^m2 || P1_name)
# Round 2 (Server): Check Validity of signature.

def send_initial_challenge(s, n1, n2, client_name):
    # Get signature to send
    message = n1 + n2 + client_name
    print("2. Sending {} message {{{}, {}, {}, MAC}}".format(client_name, n1.hex(), n2.hex(), client_name))
    s.send(authenticate(message, secret_key))

# returns (m1, m2)
def receive_response(s, n1, n2, client_name, target_name):
    msg = s.recv(1024)
    xor = xor_bytes(n1, n2)
    assert len(xor) == RANDOM_NUMBER_BYTES
    m1 = msg[0:16]
    m2 = msg[16:32]
    xor_from_message = msg[32:32+len(xor)]
    name_from_message = msg[RANDOM_NUMBER_BYTES * 3 : len(msg) - KEY_SIZE_BITS // 8]
    print("4. Received {{{}, {}, {}, {}, {}, MAC}} from {}".format(m1.hex(), m2.hex(), xor_from_message.hex(), client_name))
    if not verify(msg):
        print("Failed to verify with {}".format(target_name))
        print("Either files do not match or there is malice in play")
        sys.exit(1)
    if name_from_message != target_name:
        print("Failed to verify with {}: Name doesn't match".format(target_name))
        print("This means {} isn't following the protocol or an impostor is among us".format(target_name))
        sys.exit(1)
    if xor != xor_from_message:
        print("Failed to verify with {}: failed to authenticate with the given challenge".format(target_name))
        print("This means {} isn't following the protocol or an impostor is among us".format(target_name))
        sys.exit(1)
    print("5. MAC, xor, and name verified")
    return (m1, m2)

def respond_to_challenge(s, m1, m2, client_name):
    xor = xor_bytes(m1, m2)
    assert len(xor) == RANDOM_NUMBER_BYTES
    message = xor + client_name
    s.send(authenticate(message, secret_key))

def main():
    if len(sys.argv) != 5:
        help()
        return

    password_file = sys.argv[1]
    client_name = str.encode(sys.argv[2]) + bytes([0])
    ip, port = parse_server(sys.argv[3])
    target_name = str.encode(sys.argv[4]) + bytes([0])

    assert len(client_name) < MAX_NAME_LENGTH
    assert len(target_name) < MAX_NAME_LENGTH

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to {}:{}".format(ip, port))
    s.connect((ip, port))
    print("Connected")

    global secret_key
    secret_key = sha3_file(password_file)
    print("1. Derrived shared secret key from file")

    n1 = generate_random(RANDOM_NUMBER_BYTES)
    n2 = generate_random(RANDOM_NUMBER_BYTES)
    # step 2
    send_initial_challenge(s, n1, n2, client_name)
    # step 4 and 5
    m1, m2 = receive_response(s, n1, n2, client_name, target_name)
    # step 6
    respond_to_challenge(s, m1, m2, client_name)

    print("Verified with {}".format(target_name))

main()
