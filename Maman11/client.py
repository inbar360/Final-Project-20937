import socket
import struct

HOST = "localhost"
PORT = 5000


def client():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))

    # Pack the binary data
    data = struct.pack("<H", 12)

    # Send the data
    sock.sendall(data)

    sock.close()


if __name__ == '__main__':
    client()
