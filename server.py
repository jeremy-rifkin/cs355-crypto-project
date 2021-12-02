#!/usr/bin/python3
# Server for exchange. Sets up communication method.

import socket
import sys
from common import *

def help():
    print("usage: ./server.py password_file server_name")

secret_key = None

# returns (n1, n2, name)
def receive_initial_challenge(conn):
    msg = conn.recv(1024)
    n1, n2, name_from_message = parse_message(2, msg)
    print("2. Received message {{{}, {}, {}, MAC}} from (self-identified) {}".format(n1.hex(), n2.hex(), name_from_message, name_from_message))
    if not verify(msg, secret_key):
        print("Failed to verify with {}: Invalid authentication on initial challenge.".format(name_from_message))
        print("Either files do not match or there is malice in play")
        raise VerificationFailure()
    print("3. MAC verifies")
    return (n1, n2, name_from_message)

# returns (m1, m2)
def respond_to_challenge_and_send_challenge(conn, n1, n2, client_name, server_name):
    xor = xor_bytes(n1, n2)
    assert len(xor) == RANDOM_NUMBER_BYTES
    m1 = generate_random(RANDOM_NUMBER_BYTES)
    m2 = generate_random(RANDOM_NUMBER_BYTES)
    message = m1 + m2 + xor + server_name
    print("4. Sending {} message {{{}, {}, {}, {}, MAC}}".format(client_name, m1.hex(), m2.hex(), xor.hex(), server_name))
    conn.send(authenticate(message, secret_key))
    return (m1, m2)

def verify_challenge_response(conn, m1, m2, client_name):
    msg = conn.recv(1024)
    xor_from_message, name_from_message = parse_message(6, msg)
    xor = xor_bytes(m1, m2)
    assert len(xor) == RANDOM_NUMBER_BYTES
    print("6. Received {{{}, {}, MAC}} from {}".format(xor_from_message.hex(), name_from_message, client_name))
    if not verify(msg, secret_key):
        print("Failed to verify with {}".format(client_name))
        print("Either files do not match or there is malice in play")
        raise VerificationFailure()
    if name_from_message != client_name:
        print("Failed to verify with {}: Name doesn't match".format(client_name))
        print("This means {} isn't following the protocol or an impostor is among us".format(client_name))
        raise VerificationFailure()
    if xor != xor_from_message:
        print("Failed to verify with {}: failed to authenticate with the given challenge".format(client_name))
        print("This means {} isn't following the protocol or an impostor is among us".format(client_name))
        raise VerificationFailure()
    print("7. MAC, xor, and name verified")

def main():
    if len(sys.argv) != 3:
        help()
        return

    password_file = sys.argv[1]
    server_name = str.encode(sys.argv[2]) + bytes([0])

    assert len(server_name) < MAX_NAME_LENGTH

    port = 1138
    host = "0.0.0.0"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    print("Server running on {}:{}".format(str(host), port))
    s.listen()

    global secret_key
    secret_key = sha3_file(password_file)
    print("1. Derrived shared secret key from file")

    while True:
        client_name = None
        try:
            conn, addr = s.accept()
            print("=================================================")
            print("Accepting connection from {}:{}".format(*addr))

            n1, n2, client_name = receive_initial_challenge(conn)
            m1, m2 = respond_to_challenge_and_send_challenge(conn, n1, n2, client_name, server_name)
            verify_challenge_response(conn, m1, m2, client_name)

            print("Verified successfully with {}".format(client_name))
        except VerificationFailure:
            print("Failed to verify with {}".format("<unknown client>" if client_name is None else client_name))
        except KeyboardInterrupt:
            break
        conn.close()

main()
