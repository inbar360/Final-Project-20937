from enum import Enum
import uuid
import os
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.Padding import unpad

default_version = 3
users_directory = 'users'

requests_formats = {
    825: '255s',
    826: '255s 160s',
    827: '255s',
    828: '<I I H H 255s 1024s',
    900: '255s',
    901: '255s',
    902: '255s'
}

responses_formats = {
    1600: '<B H I 16s',
    1601: '<B H I',
    1602: '<B H I 16s 128s',
    1603: '<B H I 16s I 255s 4s',
    1604: '<B H I 16s',
    1605: '<B H I 16s 128s',
    1606: '<B H I 16s',
    1607: '<B H I'
}


def create_uuid() -> bytes:
    """
    Creates a new uuid and returns its byte form.

    :returns: The new uuid in bytes format.
    """
    return uuid.uuid4().bytes


def decodes_utf8(to_decode: bytes) -> str:
    """
    Decodes the given bytes object to a utf-8 string.

    :param to_decode: The byte object to decode into a utf-8 string.

    :returns: The decoded utf-8 string.
    """
    return to_decode.decode('utf-8', 'ignore')


def create_aes_key(key_size=256) -> bytes:
    """
    Creates a new key containing the provided key_size number of bits.

    :param key_size: The size of the new key in bits.

    :returns: A bytes object representing the newly created key.
    """
    return get_random_bytes(key_size // 8)


def encrypt_aes_key(aes_key: bytes, public_key: RsaKey) -> bytes:
    """
    Encrypts the given AES key using the provided Public key.

    :param aes_key: The AES key to encrypt.
    :param public_key: The public key used to encrypt the AES key.

    :returns: A bytes object representing the encrypted AES key.
    """
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher.encrypt(aes_key)
    # Return the encrypted key.
    return encrypted_aes_key


def decrypt_file_using_aes_key(file_path: str, aes_key: bytes) -> bytes:
    """
    Decrypts the data of the file with the provided path.

    :param file_path: The path to the file whose data is to be decrypted.
    :param aes_key: The AES key used to decrypt the file data.

    :returns: A bytes object representing the decrypted data.
    """
    iv = bytes(16)

    with open(file_path, 'rb') as file:
        encrypted_data = file.read()

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    return decrypted_data


def create_directory(dir_name: str) -> bool:
    """
    Creates a directory under the 'users' directory to store client files.

    :param dir_name: The name of the directory to be created.

    :return: A boolean indicating whether the directory was successfully created.
    """
    try:
        dir_path = os.path.join(users_directory, dir_name)
        os.makedirs(dir_path)
    except OSError:
        return False
    return True


# This method is used to return the path the client's file will be saved into.
def get_client_file_path(client_id: str, file_name: str) -> str:
    """
    Retrieve the file path for the client with the specified id.

    :param client_id: The client's id.
    :param file_name: The client's file name.

    :return: The path for the wanted file.
    """
    return os.path.join(users_directory, client_id, file_name)


def remove_client_file(file_path: str):
    os.remove(file_path)


# An enum class for client requests and their codes.
class RequestCodes(Enum):
    """
    An Enum class for client requests and their respective codes.
    """
    REGISTRATION = 825
    SENDING_PUBLIC_KEY = 826
    RECONNECTION = 827
    SENDING_FILE = 828
    VALID_CRC = 900
    INVALID_CRC_SENDING_AGAIN = 901
    FOURTH_TIME_INVALID_CRC = 902


class ReqState(Enum):
    """
    An Enum class for states of requests and their respective codes.
    Essentially, the states represent the response code for the server.
    """
    REGISTERED_SUCCESSFULLY = 1600
    CLIENT_NAME_REGISTERED = 1601
    PUBLIC_KEY_RECEIVED = 1602
    FILE_RECEIVED_CRC = 1603
    MESSAGE_RECEIVED = 1604
    RECONNECTED_SUCCESSFULLY = 1605
    NOT_REGISTERED_OR_INVALID_KEY = 1606
    GENERAL_ERROR = 1607

    AWAIT_FILE = 1608  # Used as the response code for request 901 - 'invalid CRC, sending again'.
    AWAIT_PACKET = 1609  # Used as the response code for request 828, when it's not the final packet.
