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

		virtual bool run(tcp::socket &sock) = 0;
		std::vector<uint8_t> pack_header() const;

};

class Registration : Request {
	char name[255];

	public:
		Registration(UUID uuid, uint16_t code, uint32_t payload_size, const char name[]);

		bool run(tcp::socket &sock);
		std::vector<uint8_t> pack_registration_request();
};

class SendingPublicKey : Request {
	char name[255];
	char public_key[160];
	char encrypted_aes_key[160];

	public:
		SendingPublicKey(UUID uuid, uint16_t code, uint32_t payload_size, const char name[], const char public_key[]);
		std::string getEncryptedAesKey() const;

		bool run(tcp::socket& sock);
		std::vector<uint8_t> pack_sending_public_key_request();
};

class Reconnection : Request {
	char name[255];
	char encrypted_aes_key[160];

	public:
		Reconnection(UUID uuid, uint16_t code, uint32_t payload_size, const char name[]);
		std::string getEncryptedAesKey() const;

		bool run(tcp::socket &sock);
		std::vector<uint8_t> pack_reconnection_request();
};

class SendingFile : Request {
	uint32_t content_size;
	uint32_t orig_file_size;
	uint16_t packet_number;
	uint16_t total_packets;
	// save message content somehow.
	char cksum[4];
};

class ValidCrc : Request {
	char file_name[255];

	public:
		ValidCrc(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]);

		bool run(tcp::socket &sock);
		std::vector<uint8_t> pack_valid_crc_request();
};

class SendingCrcAgain : Request {
	char file_name[255];

	public:
		SendingCrcAgain(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]);

		bool run(tcp::socket &sock);
		std::vector<uint8_t> pack_sending_crc_again_request();
};

class InvalidCrcDone : Request {
	char file_name[255];

	public:
		InvalidCrcDone(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]);

		bool run(tcp::socket &sock);
		std::vector<uint8_t> pack_invalid_crc_done_request();
};
