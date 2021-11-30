#!/usr/bin/python3
# Server for exchange. Sets up communication method.

import socket
import sys
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA3_256

from common import RANDOM_NUMBER_BYTES, generate_random, parse_server

def help():
    print("./client.py password_file client_name target_ip:port target_name")

# Round 1 (Client): Client sends n1 || n2 || P1_Name || MAC(n1, n2, P1_Name)
# Round 1 (Server): Server sends m1 || m2 || n1 XOR n2 || P2_Name || MAC(m1, m2, n1^n2, P2_Name)
# Round 2 (Client): Check validity of signature. Send m1^m2 || P1_Name || MAC(m1^m2 || P1_name)
# Round 2 (Server): Check Validity of signature.

def roundOne(s, m1, m2, h, client_name):
    # Get signature to send
    send_data = m1 + m2 + client_name
    h.update(send_data)
    signature = h.finalize()
    send_data += signature

    return send_data

def roundTwo(s, m1, m2, h, client_name):
    msg = s.recv(1024)
    h_copy = h.copy()
    # Get XOR value of numbers to check message
    m1_num = int.from_bytes(m1, byteorder="big", signed=False)
    m2_num = int.from_bytes(m2, byteorder="big", signed=False)
    check_value = m1_num^m2_num
    check_value = check_value.to_bytes(16, "big")

    n1 = msg[0:16]
    n2 = msg[16:32]
    
    # Get XOR from message and check validity
    value_from_msg = msg[32:32+len(check_value)]
    if (check_value != value_from_msg):
        return False

    index = len(check_value) + 32
    P2 = b""
    while (msg[index] != 0):
        P2 += msg[index].to_bytes(1, "big")
        index += 1
    P2 += msg[index].to_bytes(1, "big")
    index += 1

    tag = msg[index:]
    sent_data = n1+n2+check_value + P2
    h.update(sent_data)
    h.verify(tag)

    n1_num = int.from_bytes(n1, byteorder="big", signed=False)
    n2_num = int.from_bytes(n2, byteorder="big", signed=False)
    new_value = n1_num^n2_num
    new_value = new_value.to_bytes(16, "big")
    send_data = new_value + client_name
    h_copy.update(send_data)
    signature = h_copy.finalize()
    send_data += signature

    s.send(send_data)
    return True

def main():
    if len(sys.argv) != 4:
        help()
        return

    password_file = sys.arv[1]
    client_name = str.encode(sys.argv[2]) + bytes([0])
    ip, port = parse_server(sys.argv[3])
    target_name = str.encode(sys.argv[4]) + bytes([0])

    m1 = generate_random(RANDOM_NUMBER_BYTES)
    m2 = generate_random(RANDOM_NUMBER_BYTES)
    file = open(password_file, "rb")
    key = file.read()
    h = HMAC(key, SHA3_256())
    
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print("Connected to Server.")

    send_data = roundOne(s, m1, m2, h.copy(), client_name)
    s.send(send_data)
    result = roundTwo(s, m1, m2, h.copy(), client_name)

    if (result == False):
        print("Files do not appear to match.")
    else:
        print("Files match!")

main()
