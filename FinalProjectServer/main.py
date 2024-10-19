from FinalProjectServer.server import Server

HOST = '127.0.0.1'


def main():
    server = Server(HOST)
    server.run()


if __name__ == '__main__':
    main()
