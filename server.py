# Server for exchange. Sets up communication method.

import socket
from sys import argv
from os import urandom
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.hashes import SHA3_256

Name = bytes('Bob\0', 'utf-8')

# 128-bit random numbers (16 bytes)


# Round 1 (Client): Client sends n1 || n2 || P1_Name || MAC(n1, n2, P1_Name)
# Round 1 (Server): Server sends m1 || m2 || n1 XOR n2 || P2_Name || MAC(m1, m2, n1^n2, P2_Name)
# Round 2 (Client): Check validity of signature. Send m1^m2 || P1_Name || MAC(m1^m2 || P1_name)
# Round 2 (Server): Check Validity of signature.



def get_random_number():
    num = urandom(16)
    return num

import pdb
def roundOne(conn, m1, m2, h):
    msg = conn.recv(1024)  # Check read count later
#    msg = msg.decode("utf-8")
    data = m1 + m2
    h_copy = h.copy()
    # Get message contents
    n1 = msg[0:16]
    n2 = msg[16:32]
    P2 = b''
    index = 32
    while (msg[index] != 0):
        P2 += msg[index].to_bytes(1, 'big')
        index += 1
    P2 += msg[index].to_bytes(1, 'big')
    index += 1
    
    tag = msg[index:]  # Get Signature

    # Verify signature sent
    sent_data = n1 + n2 + P2
    h.update(sent_data)

    # Verify the tag
    h.verify(tag)

    # Calculate XOR from integer values of byte arrays
    n1 = int.from_bytes(n1, byteorder='big', signed=False)
    n2 = int.from_bytes(n2, byteorder='big', signed=False)
    check_value = n1^n2
    check_value = check_value.to_bytes(16, 'big')
    data += check_value
    data += Name

    h_copy.update(m1+m2+check_value+Name)
    signature = h_copy.finalize()
    data += signature
    
    return data

def roundTwo(conn, m1, m2, h):
    msg = conn.recv(1024)
    # Get XOR value of numbers to check message
    m1_num = int.from_bytes(m1, byteorder='big', signed=False)
    m2_num = int.from_bytes(m2, byteorder='big', signed=False)
    check_value = m1_num^m2_num
    check_value = check_value.to_bytes(16, 'big')

    # Get XOR from message and check validity
    value_from_msg = msg[0:len(check_value)]
    if (check_value != value_from_msg):
        return False

    index = len(check_value)
    P2 = b''
    while (msg[index] != 0):
        P2 += msg[index].to_bytes(1, 'big')
        index += 1
    P2 += msg[index].to_bytes(1, 'big')
    index += 1

    tag = msg[index:]
    sent_data = check_value + P2
    h.update(sent_data)
    h.verify(tag)

    return True
    






def main():
    m1 = get_random_number()
    m2 = get_random_number()
    file = open('./supersecretpasswords', 'rb')
    key = file.read()    
    h = HMAC(key, SHA3_256())
    
    port = 1138
    host = socket.gethostbyname(socket.gethostname())
    print(str(host))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen()

    conn, addr = s.accept()
    send_data = roundOne(conn, m1, m2, h.copy())
    conn.send(send_data)
    result = roundTwo(conn, m1, m2, h.copy())

    if (result == False):
        print('Files do not appear to match.')
    else:
        print('Files match!')

        

    

    
    

    




main()
