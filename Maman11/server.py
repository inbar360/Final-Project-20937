import socket
import struct

HOST = "localhost"
PORT = 5000


def server():
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(1)
    print("Server listening on {}:{}".format(HOST, PORT))

    # Wait for a connection
    conn, addr = sock.accept()
    print("Connected by ", addr)

    # Receive the data
    data = conn.recv(2)
    print("Received: {!r}".format(data))

    # Unpack the binary data
    unpacked_data = struct.unpack('<H', data)
    print("Unpacked data: ", unpacked_data)
    print(type(unpacked_data[0]))
    # print(unpacked_data[0].decode('utf-8', 'ignore'))
    # print('in str', unpacked_data[0].hex())
    # print(unpacked_data[1])

    conn.close()
    sock.close()


if __name__ == '__main__':
    server()
