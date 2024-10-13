#include "request.hpp"

Request::Request(UUID uuid, uint16_t code, uint32_t payload_size) :
	uuid(uuid),
	version(VERSION),
	code(code),
	payload_size(payload_size) 
{

}

UUID Request::getUuid() const {
	return this->uuid;
}
uint8_t Request::getVersion() const {
	return this->version;
}
uint16_t Request::getCode() const {
	return this->code;
}
uint32_t Request::getPayloadSize() const {
	return this->payload_size;
}

/*
	This method packs the header for the client's request in a form of uint8_t vector.
	It creates the vector for the size of the request, and copies all request header fields into the vector.
	Numeric fields are represented in little endian order.
*/
std::vector<uint8_t> Request::pack_header() const {
	std::vector<uint8_t> req(REQUEST_HEADER_SIZE + payload_size);

	// Saving the numeric types that ar bigger than one byte in little endian order.
	uint16_t code_le = boost::endian::native_to_little(code);
	uint32_t payload_size_le = boost::endian::native_to_little(payload_size);

	// Saving the bytes in little endian order as a byte array.
	uint8_t *code_le_ptr = reinterpret_cast<uint8_t *>(&code_le);
	uint8_t *payload_size_le_ptr = reinterpret_cast<uint8_t *>(&payload_size_le);

	// Adding all fields to the vector.
	std::copy(uuid.begin(), uuid.end(), req.begin());
	req[sizeof(uuid)] = version;
	std::copy(code_le_ptr, code_le_ptr + sizeof(code_le), req.begin() + sizeof(uuid) + sizeof(version));
	std::copy(payload_size_le_ptr, payload_size_le_ptr + sizeof(payload_size_le), req.begin() + sizeof(uuid) + sizeof(version) + sizeof(code));

	return req;
}

Registration::Registration(UUID uuid, uint16_t code, uint32_t payload_size, const char name[]):
	Request(uuid, code, payload_size) 
{
	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(name);
	size_t amt = (len >= NAME_LENGTH) ? (NAME_LENGTH - 1) : len;

	memset(this->name, 0, sizeof(this->name));
	strncpy_s(this->name, name, amt);
}

bool Registration::run(tcp::socket &sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_registration_request();

	while (times_sent != 3) {
		try {
			// Send the request to the server via the provided socket.
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and payload_size
			std::vector<uint8_t> response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = get_response_code(response_header);
			uint32_t response_payload_size = get_response_payload_size(response_header);

			// Receive payload from the server, save it's length in a parameter length.
			std::vector<uint8_t> response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::REGISTRATION_SUCCEEDED_C || response_payload_size != response_payload_sizes(response_code) || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error.");
			}
			// The Registration succeeded, set the uuid to the id the server responded with.
			for (int i = 0; i < response_payload.size(); i++) {
				uuid.data[i] = (response_payload[i] >> 4);
				uuid.data[i+1] = (response_payload[i] & 0xf);
			}
			// If this code is reached, there was no error and the Registration was successful, so we break from the loop.
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}

	// If the i reached 3, return false.
	if (times_sent == 3) {
		return false;
	}
	// If the client succeeded, return true.
	return true;
}

/*
	This method packs the header and payload for the registration request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> Registration::pack_registration_request() {
	std::vector<uint8_t> req = pack_header();
	
	std::copy(name, name + sizeof(name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}


SendingPublicKey::SendingPublicKey(UUID uuid, uint16_t code, uint32_t payload_size, const char name[], const char public_key[]):
	Request(uuid, code, payload_size)
{
	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(name);
	size_t amt = (len >= NAME_LENGTH) ? (NAME_LENGTH - 1) : len;

	memset(this->name, 0, sizeof(this->name));
	strncpy_s(this->name, name, amt);

	// Fill this->public_key with null terminator, then copy a max of 160 chars from the provided public key.
	len = strlen(public_key);
	amt = (len > PUBLIC_KEY_LENGTH) ? PUBLIC_KEY_LENGTH : len;

	memset(this->public_key, 0, sizeof(this->public_key));
	strncpy_s(this->public_key, public_key, amt);

	memset(this->encrypted_aes_key, 0, sizeof(this->encrypted_aes_key));
}

std::string SendingPublicKey::getEncryptedAesKey() const {
	std::string str_key(this->encrypted_aes_key);
	return str_key;
}

bool SendingPublicKey::run(tcp::socket& sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_sending_public_key_request();

	while (times_sent != 3) {
		try {
			// Send the request to the server via the provided socket.
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and payload_size
			std::vector<uint8_t> response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = get_response_code(response_header);
			uint32_t response_payload_size = get_response_payload_size(response_header);

			// Receive payload from the server, save it's length in a parameter length.
			std::vector<uint8_t> response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::PUBLIC_KEY_RECEIVED_C || response_payload_size != response_payload_sizes(response_code) || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error.");
			}

			// Copy the id from the payload, and check if it's the correct client id.
			std::vector<uint8_t> payload_id(sizeof(uuid));
			std::copy(response_payload.begin(), response_payload.begin() + sizeof(uuid), payload_id.begin());
			if (!id_vectors_match(payload_id, uuid)) {
				throw std::invalid_argument("server responded with an error.");
			}

			// Copy the encrypted aes key content from the response_payload vector into the parameter encrypted_aes_key, then break from the loop.
			std::copy(response_payload.begin() + sizeof(uuid), response_payload.end(), this->encrypted_aes_key);
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}

	// If the i reached 3, return false.
	if (times_sent == 3) {
		return false;
	}
	// If the client succeeded, return true.
	return true;
}

/*
	This method packs the header and payload for the sending public key request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> SendingPublicKey::pack_sending_public_key_request() {
	std::vector<uint8_t> req = pack_header();

	std::copy(name, name + sizeof(name), req.begin() + REQUEST_HEADER_SIZE);
	std::copy(public_key, public_key + sizeof(public_key), req.begin() + REQUEST_HEADER_SIZE + sizeof(name));

	return req;
}


Reconnection::Reconnection(UUID uuid, uint16_t code, uint32_t payload_size, const char name[]): 
	Request(uuid, code, payload_size)
{
	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(name);
	size_t amt = (len >= NAME_LENGTH) ? (NAME_LENGTH - 1) : len;

	memset(this->name, 0, sizeof(this->name));
	strncpy_s(this->name, name, amt);

	memset(this->encrypted_aes_key, 0, sizeof(this->encrypted_aes_key));
}

std::string Reconnection::getEncryptedAesKey() const {
	std::string str_key(this->encrypted_aes_key);
	return str_key;
}

bool Reconnection::run(tcp::socket &sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_reconnection_request();

	while (times_sent != 3) {
		try {
			// Send the request to the server via the provided socket.
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and payload_size
			std::vector<uint8_t> response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = get_response_code(response_header);
			uint32_t response_payload_size = get_response_payload_size(response_header);

			// Receive payload from the server, save it's length in a parameter length.
			std::vector<uint8_t> response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::RECONNECTION_SUCCEEDED_C || response_payload_size != response_payload_sizes(response_code) || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error.");
			}

			// Copy the id from the payload, and check if it's the correct client id.
			std::vector<uint8_t> payload_id(sizeof(uuid));
			std::copy(response_payload.begin(), response_payload.begin() + sizeof(uuid), payload_id.begin());
			if (!id_vectors_match(payload_id, uuid)) {
				throw std::invalid_argument("server responded with an error.");
			}

			// Copy the encrypted aes key content from the response_payload vector into the parameter encrypted_aes_key, then break from the loop.
			std::copy(response_payload.begin() + sizeof(uuid), response_payload.end(), this->encrypted_aes_key);
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}
	// If the i reached 3, return false.
	if (times_sent == 3) {
		return false;
	}
	// If the client succeeded, return true.
	return true;
}

/*
	This method packs the header and payload for the reconnection request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> Reconnection::pack_reconnection_request() {
	std::vector<uint8_t> req = pack_header();

	std::copy(name, name + sizeof(name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}




ValidCrc::ValidCrc(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]) :
	Request(uuid, code, payload_size)
{
	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(file_name);
	size_t amt = (len >= NAME_LENGTH) ? (NAME_LENGTH - 1) : len;

	memset(this->file_name, 0, sizeof(this->file_name));
	strncpy_s(this->file_name, file_name, amt);
}

bool ValidCrc::run(tcp::socket &sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_valid_crc_request();

	while (times_sent != 3) {
		try {
			// Send the request to the server via the provided socket.
			boost::asio::write(sock, boost::asio::buffer(request));

			// Receive header from the server, get response code and payload_size
			std::vector<uint8_t> response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = get_response_code(response_header);
			uint32_t response_payload_size = get_response_payload_size(response_header);

			// Receive payload from the server, save it's length in a parameter length.
			std::vector<uint8_t> response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::MESSAGE_RECEIVED_C || response_payload_size != response_payload_sizes(response_code) || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error.");
			}

			// Copy the id from the payload, and check if it's the correct client id.
			std::vector<uint8_t> payload_id(sizeof(uuid));
			std::copy(response_payload.begin(), response_payload.begin() + sizeof(uuid), payload_id.begin());
			if (!id_vectors_match(payload_id, uuid)) {
				throw std::invalid_argument("server responded with an error.");
			}
			// If the id provided by the server is correct, break from the loop and return true.
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}
	// If the i reached 3, return false.
	if (times_sent == 3) {
		return false;
	}
	// If the client succeeded, return true.
	return true;
}

/*
	This method packs the header and payload for the valid crc request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> ValidCrc::pack_valid_crc_request() {
	std::vector<uint8_t> req = pack_header();

	std::copy(file_name, file_name + sizeof(file_name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}

SendingCrcAgain::SendingCrcAgain(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]):
	Request(uuid, code, payload_size)
{
	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(file_name);
	size_t amt = (len >= NAME_LENGTH) ? (NAME_LENGTH - 1) : len;

	memset(this->file_name, 0, sizeof(this->file_name));
	strncpy_s(this->file_name, file_name, amt);
}

bool SendingCrcAgain::run(tcp::socket &sock) {


	return true;
}

/*
	This method packs the header and payload for the sending crc again request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> SendingCrcAgain::pack_sending_crc_again_request() {
	std::vector<uint8_t> req = pack_header();

	std::copy(file_name, file_name + sizeof(file_name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}

InvalidCrcDone::InvalidCrcDone(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]):
	Request(uuid, code, payload_size)
{
	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(file_name);
	size_t amt = (len >= NAME_LENGTH) ? (NAME_LENGTH - 1) : len;

	memset(this->file_name, 0, sizeof(this->file_name));
	strncpy_s(this->file_name, file_name, amt);
}

bool InvalidCrcDone::run(tcp::socket &sock) {


	return true;
}

/*
	This method packs the header and payload for the invalid crc done request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> InvalidCrcDone::pack_invalid_crc_done_request() {
	std::vector<uint8_t> req = pack_header();

	std::copy(file_name, file_name + sizeof(file_name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}
