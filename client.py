#!/usr/bin/python3
# Server for exchange. Sets up communication method.

import socket
import sys

from common import *

def help():
    print("usage: ./client.py password_file client_name target_ip:port target_name")

secret_key = None

# returns (n1, n2)
def send_initial_challenge(s, client_name, target_name):
    n1 = generate_random(RANDOM_NUMBER_BYTES)
    n2 = generate_random(RANDOM_NUMBER_BYTES)
    message = n1 + n2 + client_name
    print("2. Sending {} message {{{}, {}, {}, MAC}}".format(target_name, n1.hex(), n2.hex(), client_name))
    s.send(authenticate(message, secret_key))
    return (n1, n2)

# returns (m1, m2)
def receive_response(s, n1, n2, client_name, target_name):
    msg = s.recv(1024)
    if not msg:
        print("Failed to verify: Connection dropped by server")
        sys.exit(1)
    m1, m2, xor_from_message, name_from_message = parse_message(4, msg)
    xor = xor_bytes(n1, n2)
    assert len(xor) == RANDOM_NUMBER_BYTES
    print("4. Received {{{}, {}, {}, {}, MAC}} from {}".format(m1.hex(), m2.hex(), xor_from_message.hex(), name_from_message, client_name))
    if not verify(msg, secret_key):
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

def respond_to_challenge(s, m1, m2, client_name, target_name):
    xor = xor_bytes(m1, m2)
    assert len(xor) == RANDOM_NUMBER_BYTES
    message = xor + client_name
    print("6. Sending {} message {{{}, {}, MAC}}".format(target_name, xor.hex(), client_name))
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

    # step 2
    n1, n2 = send_initial_challenge(s, client_name, target_name)
    # step 4 and 5
    m1, m2 = receive_response(s, n1, n2, client_name, target_name)
    # step 6
    respond_to_challenge(s, m1, m2, client_name, target_name)

    print("Verified successfully with {}".format(target_name))

main()
