# Server for exchange. Sets up communication method.

import socket
from sys import argv
from os import urandom

# 128-bit random numbers (16 bytes)


# Round 1 (Client): Client sends n1 and n2 (random numbers)
# Round 1 (Server): Server sends m1 and m2 (random numbers) and n1 XOR x2
# Round 2 (Client): Check validity of n1 and n2. Client sends m1 XOR m2
# Round 2 (Server): Check Validity of m1 and m2



def get_random_number():
    num = urandom(16)
    return num



def roundOne(conn, m1, m2):
    msg = conn.recv(1024)  # Check read count later
#    msg = msg.decode("utf-8")
    data = m1 + m2

    n1 = msg[0:16]
    n2 = msg[16:32]
    tag = msg[32:]

    verify()

    n1 = int.from_bytes(n1, byteorder='big', signed=False)
    n2 = int.from_bytes(n2, byteorder='big', signed=False)
    check_value = n1^n2
    check_value = c.to_bytes(16, 'big')
    data += check_value

    return data

def roundTwo(conn, m1, m2):
    msg = conn.recv(1024)
    m1Recv = msg[0:16]
    m2Recv = msg[16:32]
    tag = msg[32:]

    verified = verify()
    if (verifited == False):
        return False
    elif (m1 == m1Recv and m2 == m2Recv):
        return True
    else:
        return False

    






def main():
    # Initialize socket and send starting message
    if len(argv) < 2:
        print('Specify a port number.')
        return

    m1 = get_random_number()
    m2 = get_randum_number()
    file = open('./supersecretpasswords', 'rb')
    file_data = file.read()
    
    port = int(argv[1])
    host = socket.gethostbyname(socket.gethostname())
    print(str(host))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen()

    conn, addr = s.accept()
    send_data = roundOne(conn, m1, m2)
    conn.send(send_data)
    result = roundTwo(conn, m1, m2)

    if (result == False):
        print('Files do not appear to match.')
    else:
        print('Files match!')

        

    

    
    

    




main()
