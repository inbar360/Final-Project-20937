#include "utils.hpp"

class Request {
	protected:
		UUID uuid;
		uint8_t version;
		uint16_t code;
		uint32_t payload_size;

	public:
		Request(UUID uuid, uint16_t code, uint32_t payload_size);

		UUID getUuid() const;
		uint8_t getVersion() const;
		uint16_t getCode() const;
		uint32_t getPayloadSize() const;

		// Pure Virtual function, each request derived class will implement this function.
		virtual int run(tcp::socket &sock) = 0;
		// This method packs the request header fields into a uint8_t vector of size payload_size and returns it.
		std::vector<uint8_t> pack_header() const;
};

class Registration : public Request {
	char name[NAME_SIZE];

	public:
		Registration(UUID uuid, uint16_t code, uint32_t payload_size, const char name[]);

		// This method runs the Registration request and gets the server's response.
		int run(tcp::socket &sock);
		// This method packs the Registration Request fields into a uint8_t vector and returns it.
		std::vector<uint8_t> pack_registration_request() const;
};

class SendingPublicKey : public Request {
	char name[NAME_SIZE];
	char public_key[KEY_LENGTH];
	char encrypted_aes_key[ENC_AES_KEY_LENGTH];

	public:
		SendingPublicKey(UUID uuid, uint16_t code, uint32_t payload_size, const char name[], const char public_key[]);
		std::string getEncryptedAesKey() const;

		// This method runs the Sending Public Key request and gets the server's response.
		int run(tcp::socket& sock);
		// This method packs the Sending Public Key Request fields into a uint8_t vector and returns it.
		std::vector<uint8_t> pack_sending_public_key_request() const;
};

class Reconnection : public Request {
	char name[NAME_SIZE];
	char encrypted_aes_key[ENC_AES_KEY_LENGTH];

	public:
		Reconnection(UUID uuid, uint16_t code, uint32_t payload_size, const char name[]);
		std::string getEncryptedAesKey() const;

		// This method runs the Reconnection request and gets the server's response.
		int run(tcp::socket &sock);
		// This method packs the Reconnection Request fields into a uint8_t vector and returns it.
		std::vector<uint8_t> pack_reconnection_request() const;
};

class SendingFile : public Request {
	uint32_t content_size;
	uint32_t orig_file_size;
	uint16_t packet_number;
	uint16_t total_packets;
	char file_name[NAME_SIZE];
	std::string encrypted_file_content;
	char encrypted_content[CONTENT_SIZE_PER_PACKET];
	char cksum[4];

	public:
		SendingFile(UUID uuid, uint16_t code, uint32_t payload_size, uint32_t content_size, uint32_t orig_file_size, uint16_t total_packets, const char file_name[], std::string encrypted_file_content);
		void setEncryptedContent(const char encrypted_content[]);
		std::string getEncryptedContent() const;
		std::string getCksum() const;

		// This method runs the Sending File request and gets the server's response.
		int run(tcp::socket& sock);
		// This method packs the Sending File Request fields into a uint8_t vector and returns it.
		std::vector<uint8_t> pack_sending_file_request() const;
		// This method saves the response's content size in a uint32_t variable, reorders it from little endian order to the OS's native endianess ordering and returns it.
		uint32_t getPayloadContentSize(std::vector<uint8_t> payload);
};

class ValidCrc : public Request {
	char file_name[NAME_SIZE];

	public:
		ValidCrc(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]);

		// This method runs the Valid CRC request and gets the server's response.
		int run(tcp::socket &sock);
		// This method packs the Valid CRC Request fields into a uint8_t vector and returns it.
		std::vector<uint8_t> pack_valid_crc_request() const;
};

class SendingCrcAgain : public Request {
	char file_name[NAME_SIZE];

	public:
		SendingCrcAgain(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]);

		// This method runs the Sending CRC Again request and gets the server's response.
		int run(tcp::socket &sock);
		// This method packs the Sending CRC Again Request fields into a uint8_t vector and returns it.
		std::vector<uint8_t> pack_sending_crc_again_request() const;
};

class InvalidCrcDone : public Request {
	char file_name[NAME_SIZE];

	public:
		InvalidCrcDone(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]);

		// This method runs the Invalid CRC Done request and gets the server's response.
		int run(tcp::socket &sock);
		// This method packs the Invalid CRC Done Request fields into a uint8_t vector and returns it.
		std::vector<uint8_t> pack_invalid_crc_done_request() const;
};
