from Crypto.PublicKey.RSA import RsaKey


class Client:
    """
    Represents a client in the system, storing essential client information.

    Attributes:
        _name (str): The client's name.
        _public_key (RsaKey | None): The client's public RSA key, used for encryption, or None if not set.
        _aes_key (bytes | None): The AES key used for encryption or None if not set.
        _file_name (str | None): The name of the file associated with the client, or None if not set.
        _tot_packets (int | None): The total number of file packets expected, or None if not set.
        _packets (dict[int, bytes]): A dictionary mapping packet indices to their encrypted content.
        _crc (str | None): The checksum (CRC) of the file for integrity verification, or None if not set.
        _content_size (int | None): The size of the content being handled, or None if not set.
    """
    def __init__(self, name: str):
        self._name: str = name
        self._public_key: RsaKey | None = None
        self._last_seen = None
        self._aes_key: bytes | None = None
        self._file_name: str | None = None
        self._tot_packets: int | None = None
        self._packets: dict[int, bytes] = {}
        self._crc: str | None = None
        self._content_size: int | None = None

    def set_public_key(self, key: RsaKey) -> None:
        self._public_key = key

    def set_aes_key(self, key: bytes) -> None:
        self._aes_key = key

    def set_file_name(self, file_name: str) -> None:
        self._file_name = file_name

    def set_tot_packets(self, tot_packets: int) -> None:
        self._tot_packets = tot_packets

    def set_crc(self, crc: str) -> None:
        self._crc = crc

    def set_content_size(self, content_size: int) -> None:
        self._content_size = content_size

    def get_name(self) -> str:
        return self._name

    def get_public_key(self) -> RsaKey:
        return self._public_key

    def get_aes_key(self) -> bytes:
        return self._aes_key

    def get_file_name(self) -> str:
        return self._file_name

    def get_tot_packets(self):
        return self._tot_packets

    def get_packets(self) -> dict[int, bytes]:
        return self._packets

    def get_crc(self) -> str:
        return self._crc

    def get_content_size(self) -> int:
        return self._content_size

    # This method clears the packets dictionary in case the client sends from the beginning.
    def clear_dict(self) -> None:
        self._packets.clear()

    # This method adds the data given using the provided packet number as a key.
    def add_packet_data(self, packet_number: int, data: bytes) -> None:
        self._packets[packet_number] = data

    def received_entire_file(self) -> bool:
        return len(self._packets) == self._tot_packets
