import socket
import struct
import utils
from abc import ABC, abstractmethod

RESP_HEADER_FORMAT = '<B H I'
PAYLOAD_SIZES = {
    1600: 16,
    1601: 0,
    1602: 144,
    1603: 279,
    1604: 16,
    1605: 144,
    1606: 16,
    1607: 0
}


class Response(ABC):
    def __init__(self, code, payload_size):
        self._code = code
        self._payload_size = payload_size
        self._version = utils.default_version

    def pack_request_header(self) -> bytes:
        """
        Pack the header using the struct module.

        :return: A bytes object containing the header fields - version, code, and the payload size.
        """
        return struct.pack(RESP_HEADER_FORMAT, self._version, self._code, self._payload_size)

    @abstractmethod
    def run(self, conn: socket.socket) -> None:
        pass


class RegistrationSucceeded(Response):
    def __init__(self, code, payload_size, client_id):
        super().__init__(code, payload_size)
        self._client_id = client_id

    def pack_registration_succeeded(self) -> bytes:
        """
        Pack the registration succeeded response using the struct module.

        :return: A bytes object containing the registration succeeded response fields -
                 version, code, payload size, and the client id.
        """
        return super().pack_request_header() + struct.pack(utils.responses_formats[self._code], self._client_id)

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_registration_succeeded()
        conn.sendall(packed_msg)


class RegistrationFailed(Response):
    def __init__(self, code, payload_size):
        super().__init__(code, payload_size)

    def pack_registration_failed(self) -> bytes:
        """
        Pack the registration failed response using the struct module.

        :return: A bytes object containing the registration failed response fields -
                 version, code, and the payload size.
        """
        return super().pack_request_header()

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_registration_failed()
        conn.sendall(packed_msg)


class PublicKeyReceived(Response):
    def __init__(self, code, payload_size, client_id, enc_aes_key):
        super().__init__(code, payload_size)
        self._client_id = client_id
        self._enc_aes_key = enc_aes_key

    def pack_public_key_received(self) -> bytes:
        """
        Pack the public key received response using the struct module.

        :return: A bytes object containing the public key received response fields -
                 version, code, payload size, client id, and the encrypted AES key.
        """
        return super().pack_request_header() + \
            struct.pack(utils.responses_formats[self._code], self._client_id, self._enc_aes_key)

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_public_key_received()
        conn.sendall(packed_msg)


class FileReceivedCrc(Response):
    def __init__(self, code, payload_size, client_id, content_size, file_name, cksum):
        super().__init__(code, payload_size)
        self._client_id = client_id
        self._content_size = content_size
        self._file_name = file_name
        self._cksum = cksum

    def pack_file_received_crc(self) -> bytes:
        """
        Pack the file received crc response using the struct module.

        :return: A bytes object containing the file received crc response fields -
                 version, code, payload size, client id, content size, file name, and the cksum.
        """
        return super().pack_request_header() + struct.pack(utils.responses_formats[self._code],
                                                           self._client_id, self._content_size,
                                                           self._file_name, self._cksum)

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_file_received_crc()
        conn.sendall(packed_msg)


class MessageReceived(Response):
    def __init__(self, code, payload_size, client_id):
        super().__init__(code, payload_size)
        self._client_id = client_id

    def pack_message_received(self) -> bytes:
        """
        Pack the message received response using the struct module.

        :return: A bytes object containing the message received response fields -
                 version, code, payload size, and the client id.
        """
        return super().pack_request_header() + struct.pack(utils.responses_formats[self._code], self._client_id)

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_message_received()
        conn.sendall(packed_msg)


class ReconnectionSucceeded(Response):
    def __init__(self, code, payload_size, client_id, enc_aes_key):
        super().__init__(code, payload_size)
        self._client_id = client_id
        self._enc_aes_key = enc_aes_key

    def pack_reconnection_succeeded(self) -> bytes:
        """
        Pack the reconnection succeeded response using the struct module.

        :return: A bytes object containing the reconnection succeeded response fields -
                 version, code, payload size, client id, and the encrypted AES key.
        """
        return super().pack_request_header() + \
            struct.pack(utils.responses_formats[self._code], self._client_id, self._enc_aes_key)

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_reconnection_succeeded()
        conn.sendall(packed_msg)


class ReconnectionFailed(Response):
    def __init__(self, code, payload_size, client_id):
        super().__init__(code, payload_size)
        self._client_id = client_id

    def pack_reconnection_failed(self):
        """
        Pack the reconnection failed response using the struct module.

        :return: A bytes object containing the reconnection failed response fields -
                 version, code, payload size, and the client id.
        """
        return super().pack_request_header() + struct.pack(utils.responses_formats[self._code], self._client_id)

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_reconnection_failed()
        conn.sendall(packed_msg)


class GeneralError(Response):
    def __init__(self, code, payload_size):
        super().__init__(code, payload_size)

    def pack_general_error(self):
        """
        Pack the general error response using the struct module.

        :return: A bytes object containing the general error response fields -
                 version, code, and the payload size.
        """
        return super().pack_request_header()

    def run(self, conn: socket.socket) -> None:
        packed_msg = self.pack_general_error()
        conn.sendall(packed_msg)
