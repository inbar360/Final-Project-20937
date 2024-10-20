from clients import Client
import socket
import struct
from utils import ReqState, requests_formats, encrypt_aes_key, RequestCodes, decodes_utf8
from requests_handling import requests_functions
from responses import PAYLOAD_SIZES
import responses

HEADER_SIZE = 23
HEADER_FORMAT = "<16s B H I"


class Server:
    def __init__(self, host: str, default_port=1256):
        port = default_port
        try:
            file = open('port.info', 'r')
            port = int(file.read())
        except OSError:
            print('Warning: file \'port.info\' does not exist. Port remained default.')
        except ValueError:
            print('Error: file \'port.info\' does not contain wanted data. Port remained default.')
        finally:
            self._host: str = host
            self._port: int = port
            self._addr = (self._host, self._port)
            self._clients: dict[bytes, Client] = {}  # dict of the structure 'UUID : CLIENT'

    def get_addr(self):
        return self._addr

    # This function returns the registered client with the provided UUID.
    def get_client(self, client_id: bytes) -> Client:
        return self._clients[client_id]

    def get_uuid_by_name(self, name: str) -> bytes | None:
        for uid in self._clients.keys():
            if self._clients[uid].get_name() == name:
                return uid
        return None

    # Adds a Client object with the given name to the clients dictionary, using the provided UUID as the key.
    def add_client(self, client_name: str, uuid: bytes) -> None:
        self._clients[uuid] = Client(client_name)

    # This function removes the client with the provided fields if exists.
    def remove_client_if_registered(self, client_id: bytes, client_name: str) -> None:
        if self.client_registered(client_id, client_name):
            self._clients.pop(client_id)

    # This function checks if the client with the given name has already been registered.
    def name_already_registered(self, client_name: str) -> bool:
        for client in self._clients.values():
            if client.get_name() == client_name:
                return True
        return False

    # This function checks if the server has a registered client with the provided UUID.
    def client_id_registered(self, client_id: bytes) -> bool:
        if client_id in self._clients.keys():
            return True
        print("the id isn't registered.")
        return False

    # This function checks if the server has a registered client with both provided fields.
    def client_registered(self, client_id: bytes, client_name: str) -> bool:
        if self.client_id_registered(client_id):
            return self._clients[client_id].get_name() == client_name
        print("the id + name aren't registered.")
        return False

    def handle_request(self, conn: socket.socket, client_id: bytes, code: RequestCodes, payload_size: int) -> \
            tuple[ReqState, tuple | None]:
        """
        Handle receiving, unpacking, and processing the client's request.

        :param conn: The connection object responsible for transferring messages between the server and the client.
        :param client_id: The client's id.
        :param code: The request code.
        :param payload_size: The size of the request's payload.

        :return: The response code generated by the server.
        """
        # Receiving the payload from the socket.
        payload = conn.recv(payload_size)
        code_int = code.value

        # If the client gave an invalid code, return false and the error.
        if code_int not in requests_formats.keys():
            return ReqState.GENERAL_ERROR, None

        # Unpacking the payload using the formats, and calling the correct function to handle the request.
        unpacked_payload = struct.unpack(requests_formats[code_int], payload)
        return requests_functions[code_int](self, client_id, code, unpacked_payload), unpacked_payload

    def handle_response(self, conn: socket.socket, client_id: bytes, code: ReqState, unpacked_request_payload) -> None:
        """
        Handle sending the server response back to the client.

        :param conn: The connection object responsible for transferring messages between the server and the client.
        :param client_id: The client's id.
        :param code: The response code.
        :param unpacked_request_payload: The request's unpacked payload, used for accessing the newly created client id,
               in case the response is either registration suceeded (1600), or reconnection failed (1606).
        """
        code_int: int = code.value

        match code:
            case ReqState.REGISTERED_SUCCESSFULLY:
                name = decodes_utf8(unpacked_request_payload[0])
                get_id = self.get_uuid_by_name(name)
                response = responses.RegistrationSucceeded(code_int, PAYLOAD_SIZES[code_int],
                                                           client_id=get_id)
            case ReqState.CLIENT_NAME_REGISTERED:
                response = responses.RegistrationFailed(code_int, PAYLOAD_SIZES[code_int])
            case ReqState.PUBLIC_KEY_RECEIVED:
                client = self.get_client(client_id)
                pub_key = client.get_public_key()
                aes_key = client.get_aes_key()
                enc_aes_key = encrypt_aes_key(aes_key, pub_key)
                response = responses.PublicKeyReceived(code_int, PAYLOAD_SIZES[code_int], client_id, enc_aes_key)
            case ReqState.FILE_RECEIVED_CRC:
                client = self.get_client(client_id)
                response = responses.FileReceivedCrc(code_int, PAYLOAD_SIZES[code_int], client_id,
                                                     client.get_content_size(), client.get_file_name(),
                                                     client.get_crc())
            case ReqState.MESSAGE_RECEIVED:
                response = responses.MessageReceived(code_int, PAYLOAD_SIZES[code_int], client_id)
            case ReqState.RECONNECTED_SUCCESSFULLY:
                client = self.get_client(client_id)
                pub_key = client.get_public_key()
                aes_key = client.get_aes_key()
                enc_aes_key = encrypt_aes_key(aes_key, pub_key)
                response = responses.ReconnectionSucceeded(code_int, PAYLOAD_SIZES[code_int], client_id, enc_aes_key)
            case ReqState.NOT_REGISTERED_OR_INVALID_KEY:
                name = decodes_utf8(unpacked_request_payload[0])
                get_id = self.get_uuid_by_name(name)
                response = responses.ReconnectionFailed(code_int, PAYLOAD_SIZES[code_int],
                                                        client_id=get_id)
            case ReqState.GENERAL_ERROR:
                response = responses.GeneralError(code_int, PAYLOAD_SIZES[code_int])
            case _:
                return
        response.run(conn)

    def run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(self.get_addr())

        sock.listen()
        conn, address = sock.accept()

        while True:
            print("waiting for request!")
            header = conn.recv(HEADER_SIZE)

            if len(header) == 0:
                conn.close()
                break

            print("len =", len(header))
            unpacked_header = struct.unpack(HEADER_FORMAT, header)
            client_id, version, code, payload_size = unpacked_header

            print("code =", code)
            # Call a function to handle the client's request.
            response_code, unpacked_request_payload = self.handle_request(conn, client_id, RequestCodes(code),
                                                                          payload_size)
            self.handle_response(conn, client_id, response_code, unpacked_request_payload)
