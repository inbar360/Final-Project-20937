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

	// Saving the numeric types that are of size larger than one byte in little endian order.
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
	RUNNING(code);

	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(name);
	size_t amt = (len >= NAME_SIZE) ? (NAME_SIZE - 1) : len;

	memset(this->name, 0, sizeof(this->name));
	strncpy_s(this->name, name, amt);
}

int Registration::run(tcp::socket &sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.

	std::cout << "Running Registration" << std::endl;
	int times_sent = 0;
	std::vector<uint8_t> request = pack_registration_request();

	while (times_sent != MAX_REQUEST_FAILS) {
		try {
			std::cout << "trying to write to the server a vector of size - " << request.size() << std::endl;

			// Send the request to the server via the provided socket.
			size_t l = boost::asio::write(sock, boost::asio::buffer(request));
			std::cout << "wrote " << l << " bytes to the server.\n";

			// Receive header from the server, get response code and payload_size
			std::vector<uint8_t> response_header(RESPONSE_HEADER_SIZE);
			boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
			uint16_t response_code = get_response_code(response_header);
			uint32_t response_payload_size = get_response_payload_size(response_header);

			std::cout << "read response's header, payload_size = " << response_payload_size << std::endl;
			// Receive payload from the server, save it's length in a parameter length.
			std::vector<uint8_t> response_payload(response_payload_size);
			size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

			std::cout << "read response's payload\n";
			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			if (response_code != Codes::REGISTRATION_SUCCEEDED_C || response_payload_size != PayloadSize::REGISTRATION_SUCCEEDED_P || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error.");
			}

			std::cout << "response fields are valid, copying uuid and breaking.\n";
			// The Registration succeeded, set the uuid to the id the server responded with.
			std::copy(response_payload.begin(), response_payload.end(), uuid.begin());
			// If this code is reached, there was no error and the Registration was successful, so we break from the loop.
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}

	// If the i reached 3, return FAILURE.
	if (times_sent == MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the client succeeded, return SUCCESS.
	return SUCCESS;
}

/*
	This method packs the header and payload for the registration request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> Registration::pack_registration_request() const {
	std::vector<uint8_t> req = pack_header();
	
	std::copy(name, name + sizeof(name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}

SendingPublicKey::SendingPublicKey(UUID uuid, uint16_t code, uint32_t payload_size, const char name[], const char public_key[]):
	Request(uuid, code, payload_size)
{
	RUNNING(code);

	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(name);
	size_t amt = (len >= NAME_SIZE) ? (NAME_SIZE - 1) : len;

	memset(this->name, 0, sizeof(this->name));
	strncpy_s(this->name, name, amt);

	// Fill this->public_key with null terminator, then copy a max of 160 chars from the provided public key.
	len = strlen(public_key);
	amt = (len > KEY_LENGTH) ? KEY_LENGTH : len;

	memset(this->public_key, 0, sizeof(this->public_key));
	strncpy_s(this->public_key, public_key, amt);

	memset(this->encrypted_aes_key, 0, sizeof(this->encrypted_aes_key));
}

// Getting the encrypted AES key received by the server in string form.
std::string SendingPublicKey::getEncryptedAesKey() const {
	std::string str_key(this->encrypted_aes_key);
	return str_key;
}

int SendingPublicKey::run(tcp::socket& sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_sending_public_key_request();

	while (times_sent != MAX_REQUEST_FAILS) {
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
			if (response_code != Codes::PUBLIC_KEY_RECEIVED_C || response_payload_size != PayloadSize::PUBLIC_KEY_RECEIVED_P || length != response_payload_size) {
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

	// If the i reached 3, return FAILURE.
	if (times_sent == MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the client succeeded, return SUCCESS.
	return SUCCESS;
}

/*
	This method packs the header and payload for the sending public key request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> SendingPublicKey::pack_sending_public_key_request() const {
	std::vector<uint8_t> req = pack_header();

	std::copy(name, name + sizeof(name), req.begin() + REQUEST_HEADER_SIZE);
	std::copy(public_key, public_key + sizeof(public_key), req.begin() + REQUEST_HEADER_SIZE + sizeof(name));

	return req;
}

Reconnection::Reconnection(UUID uuid, uint16_t code, uint32_t payload_size, const char name[]): 
	Request(uuid, code, payload_size)
{
	RUNNING(code);

	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(name);
	size_t amt = (len >= NAME_SIZE) ? (NAME_SIZE - 1) : len;

	memset(this->name, 0, sizeof(this->name));
	strncpy_s(this->name, name, amt);

	memset(this->encrypted_aes_key, 0, sizeof(this->encrypted_aes_key));
}

// Getting the encrypted AES key received by the server in string form.
std::string Reconnection::getEncryptedAesKey() const {
	std::string str_key(this->encrypted_aes_key);
	return str_key;
}

int Reconnection::run(tcp::socket &sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_reconnection_request();

	while (times_sent != MAX_REQUEST_FAILS) {
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

			// If client could not reconnect but could register, set the new uuid and return SPECIAL, indicating registration instead of reconnection.
			if (response_code == Codes::RECONNECTION_FAILED_C && response_payload_size == PayloadSize::RECONNECTION_FAILED_P && length == response_payload_size) {
				// The Registration succeeded, set the uuid to the id the server responded with.
				std::copy(response_payload.begin(), response_payload.end(), uuid.begin());
				return SPECIAL;
			}

			// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
			else if (response_code != Codes::RECONNECTION_SUCCEEDED_C || response_payload_size != PayloadSize::RECONNECTION_SUCCEEDED_P || length != response_payload_size) {
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
	// If the i reached 3, return FAILURE.
	if (times_sent == MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the client succeeded, return SUCCESS.
	return SUCCESS;
}

/*
	This method packs the header and payload for the reconnection request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> Reconnection::pack_reconnection_request() const {
	std::vector<uint8_t> req = pack_header();

	std::copy(name, name + sizeof(name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}

SendingFile::SendingFile(UUID uuid, uint16_t code, uint32_t payload_size, uint32_t content_size, uint32_t orig_file_size, uint16_t total_packets, const char file_name[], std::string encrypted_file_content) :
	Request(uuid, code, payload_size),
	content_size(content_size),
	orig_file_size(orig_file_size),
	packet_number(0),
	total_packets(total_packets),
	encrypted_file_content(encrypted_file_content)
{
	RUNNING(code);

	// Fill this->file_name with null terminator, then copy a max of 254 chars from the provided file_name.
	size_t len = strlen(file_name);
	size_t amt = (len >= NAME_SIZE) ? (NAME_SIZE - 1) : len;

	memset(this->file_name, 0, sizeof(this->file_name));
	strncpy_s(this->file_name, file_name, amt);

	memset(this->encrypted_content, 0, sizeof(this->encrypted_content));
	memset(this->cksum, 0, sizeof(this->cksum));
}

// Setting the current packet's encrypted content.
void SendingFile::setEncryptedContent(const char encrypted_content[]) {
	// Fill this->encrypted_content with null terminator, then copy a max of 1024 chars from the provided file_name.
	size_t len = strlen(encrypted_content);
	size_t amt = (len > CONTENT_SIZE_PER_PACKET) ? CONTENT_SIZE_PER_PACKET : len;

	memset(this->encrypted_content, 0, sizeof(this->encrypted_content));
	strncpy_s(this->encrypted_content, encrypted_content, amt);
}

// Getting the current packets encrypted content in string form.
std::string SendingFile::getEncryptedContent() const {
	std::string str_encrypted_content(this->encrypted_content);
	return str_encrypted_content;
}

// Getting the cksum received by the server in string form.
std::string SendingFile::getCksum() const {
	std::string str_cksum(this->cksum);
	return str_cksum;
}

int SendingFile::run(tcp::socket& sock) {
	
	for (packet_number = 1; packet_number <= total_packets; packet_number++) {
		size_t amt_to_read = MIN(CONTENT_SIZE_PER_PACKET, content_size - (packet_number-1)*CONTENT_SIZE_PER_PACKET);
		std::string content = encrypted_file_content.substr((packet_number - 1) * CONTENT_SIZE_PER_PACKET, amt_to_read);
		setEncryptedContent(content.c_str());
		
		// Pack request fields into vector
		std::vector<uint8_t> request = pack_sending_file_request();

		try {
			// Send the request to the server via the provided socket.
			boost::asio::write(sock, boost::asio::buffer(request));
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
			packet_number--;
		}
	}

	try {
		// Receive header from the server, get response code and payload_size
		std::vector<uint8_t> response_header(RESPONSE_HEADER_SIZE);
		boost::asio::read(sock, boost::asio::buffer(response_header, RESPONSE_HEADER_SIZE));
		uint16_t response_code = get_response_code(response_header);
		uint32_t response_payload_size = get_response_payload_size(response_header);

		// Receive payload from the server, save it's length in a parameter length.
		std::vector<uint8_t> response_payload(response_payload_size);
		size_t length = boost::asio::read(sock, boost::asio::buffer(response_payload, response_payload_size));

		// If the code is not success, the payload_size for the code is not the same as the size received in the header, or the length of the payload is not the wanted length, print error.
		if (response_code != Codes::FILE_RECEIVED_CRC_C || response_payload_size != PayloadSize::FILE_RECEIVED_CRC_P || length != response_payload_size) {
			throw std::invalid_argument("server responded with an error.");
		}

		// Copy the id from the payload, and check if it's the correct client id.
		std::vector<uint8_t> payload_id(sizeof(uuid));
		std::copy(response_payload.begin(), response_payload.begin() + sizeof(uuid), payload_id.begin());
		if (!id_vectors_match(payload_id, uuid)) {
			throw std::invalid_argument("server responded with an error.");
		}

		uint32_t response_content_size = getPayloadContentSize(response_payload);
		if (content_size != response_content_size) {
			throw std::invalid_argument("server responded with an error.");
		}

		std::string response_file_name(response_payload.begin() + sizeof(uuid) + sizeof(content_size), response_payload.begin() + sizeof(uuid) + sizeof(content_size) + sizeof(file_name));
		if (!file_names_match(response_file_name, file_name)) {
			throw std::invalid_argument("server responded with an error.");
		}

		// Copy the cksum content from the response_payload vector into the parameter cksum.
		std::copy(response_payload.begin() + sizeof(uuid) + sizeof(content_size) + sizeof(file_name), response_payload.end(), this->cksum);
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return FAILURE;
	}

	return SUCCESS;
}

std::vector<uint8_t> SendingFile::pack_sending_file_request() const {
	std::vector<uint8_t> req = pack_header();

	// Saving the numeric types that are of size larger than one byte in little endian order.
	uint16_t packet_num_le = boost::endian::native_to_little(packet_number);
	uint16_t total_packets_le = boost::endian::native_to_little(total_packets);
	uint32_t content_size_le = boost::endian::native_to_little(content_size);
	uint32_t orig_file_size_le = boost::endian::native_to_little(orig_file_size);

	// Saving the bytes in little endian order as a byte array.
	uint8_t* packet_num_le_ptr = reinterpret_cast<uint8_t*>(&packet_num_le);
	uint8_t* total_packets_le_ptr = reinterpret_cast<uint8_t*>(&total_packets_le);
	uint8_t* content_size_le_ptr = reinterpret_cast<uint8_t*>(&content_size_le);
	uint8_t* orig_file_size_le_ptr = reinterpret_cast<uint8_t*>(&orig_file_size_le);

	// Adding all fields to the vector.
	std::copy(content_size_le_ptr, content_size_le_ptr + sizeof(content_size_le), req.begin() + REQUEST_HEADER_SIZE);
	std::copy(orig_file_size_le_ptr, orig_file_size_le_ptr + sizeof(orig_file_size_le), req.begin() + REQUEST_HEADER_SIZE + sizeof(content_size));
	std::copy(packet_num_le_ptr, packet_num_le_ptr + sizeof(packet_num_le), req.begin() + REQUEST_HEADER_SIZE + sizeof(content_size) + sizeof(orig_file_size));
	std::copy(total_packets_le_ptr, total_packets_le_ptr + sizeof(total_packets_le), req.begin() + REQUEST_HEADER_SIZE + sizeof(content_size) + sizeof(orig_file_size) + sizeof(packet_number));
	std::copy(file_name, file_name + sizeof(file_name), req.begin() + REQUEST_HEADER_SIZE + sizeof(content_size) + sizeof(orig_file_size) + sizeof(packet_number) + sizeof(total_packets));
	std::copy(encrypted_content, encrypted_content + sizeof(encrypted_content), req.begin() + REQUEST_HEADER_SIZE + sizeof(content_size) + sizeof(orig_file_size) + sizeof(packet_number) + sizeof(total_packets) + sizeof(file_name));

	return req;
}

uint32_t SendingFile::getPayloadContentSize(std::vector<uint8_t> payload) {
	uint8_t first = payload[sizeof(uuid)], second = payload[sizeof(uuid) + 1];
	uint8_t third = payload[sizeof(uuid) + 2], last = payload[sizeof(uuid) + 3];

	uint32_t combined = (static_cast<uint32_t>(first) << 24) | 
						(static_cast<uint32_t>(second) << 16) | 
						(static_cast<uint32_t>(third) << 8) | 
						(static_cast<uint32_t>(last));

	std::cout << "combined content size = " << combined << std::endl;

	/*
		This, in my opinion, isn't quite intuitive so I'll explain it a little:
		By the way I define the 'combined' variable, I only insert it's value, meaning,
		if the operating system operates by little-endian order, it'll reverse the bytes.
		That being said, the value received is already in little-endian so we'll need to reverse them back.
	*/
	if (boost::endian::order::native == boost::endian::order::little) {
		std::cout << "returning opposite of combined.\n";
		return boost::endian::endian_reverse(combined);
	}

	return combined;
}

ValidCrc::ValidCrc(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]) :
	Request(uuid, code, payload_size)
{
	RUNNING(code);

	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(file_name);
	size_t amt = (len >= NAME_SIZE) ? (NAME_SIZE - 1) : len;

	memset(this->file_name, 0, sizeof(this->file_name));
	strncpy_s(this->file_name, file_name, amt);
}

int ValidCrc::run(tcp::socket &sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_valid_crc_request();

	while (times_sent != MAX_REQUEST_FAILS) {
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
			if (response_code != Codes::MESSAGE_RECEIVED_C || response_payload_size != PayloadSize::MESSAGE_RECEIVED_P || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error.");
			}

			// Copy the id from the payload, and check if it's the correct client id.
			std::vector<uint8_t> payload_id(sizeof(uuid));
			std::copy(response_payload.begin(), response_payload.begin() + sizeof(uuid), payload_id.begin());
			if (!id_vectors_match(payload_id, uuid)) {
				throw std::invalid_argument("server responded with an error.");
			}
			// If the id provided by the server is correct, break from the loop and return SUCCESS.
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}
	// If the i reached 3, return FAILURE.
	if (times_sent == MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the client succeeded, return SUCCESS.
	return SUCCESS;
}

/*
	This method packs the header and payload for the valid crc request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> ValidCrc::pack_valid_crc_request() const {
	std::vector<uint8_t> req = pack_header();

	std::copy(file_name, file_name + sizeof(file_name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}

SendingCrcAgain::SendingCrcAgain(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]):
	Request(uuid, code, payload_size)
{
	RUNNING(code);

	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(file_name);
	size_t amt = (len >= NAME_SIZE) ? (NAME_SIZE - 1) : len;

	memset(this->file_name, 0, sizeof(this->file_name));
	strncpy_s(this->file_name, file_name, amt);
}

int SendingCrcAgain::run(tcp::socket &sock) {
	// Pack request fields into vector.
	std::vector<uint8_t> request = pack_sending_crc_again_request();

	try {
		// Send the request to the server via the provided socket.
		boost::asio::write(sock, boost::asio::buffer(request));
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
		return FAILURE;
	}

	return SUCCESS;
}

/*
	This method packs the header and payload for the sending crc again request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> SendingCrcAgain::pack_sending_crc_again_request() const {
	std::vector<uint8_t> req = pack_header();

	std::copy(file_name, file_name + sizeof(file_name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}

InvalidCrcDone::InvalidCrcDone(UUID uuid, uint16_t code, uint32_t payload_size, const char file_name[]):
	Request(uuid, code, payload_size)
{
	RUNNING(code);

	// Fill this->name with null terminator, then copy a max of 254 chars from the provided name.
	size_t len = strlen(file_name);
	size_t amt = (len >= NAME_SIZE) ? (NAME_SIZE - 1) : len;

	memset(this->file_name, 0, sizeof(this->file_name));
	strncpy_s(this->file_name, file_name, amt);
}

// TODO: go over this and change to fit this request.
int InvalidCrcDone::run(tcp::socket &sock) {
	// Pack request fields into vector and initialize parameter times_sent to 0.
	int times_sent = 0;
	std::vector<uint8_t> request = pack_invalid_crc_done_request();

	while (times_sent != MAX_REQUEST_FAILS) {
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
			if (response_code != Codes::MESSAGE_RECEIVED_C || response_payload_size != PayloadSize::MESSAGE_RECEIVED_P || length != response_payload_size) {
				throw std::invalid_argument("server responded with an error.");
			}

			// Copy the id from the payload, and check if it's the correct client id.
			std::vector<uint8_t> payload_id(sizeof(uuid));
			std::copy(response_payload.begin(), response_payload.begin() + sizeof(uuid), payload_id.begin());
			if (!id_vectors_match(payload_id, uuid)) {
				throw std::invalid_argument("server responded with an error.");
			}
			// If the id provided by the server is correct, break from the loop and return SUCCESS.
			break;
		}
		catch (std::exception& e) {
			std::cerr << e.what() << std::endl;
		}
		// Increment the i by 1 each iteration.
		times_sent++;
	}
	// If the i reached 3, return FAILURE.
	if (times_sent == MAX_REQUEST_FAILS) {
		return FAILURE;
	}
	// If the client succeeded, return SUCCESS.
	return SUCCESS;
}

/*
	This method packs the header and payload for the invalid crc done request in a form of uint8_t vector.
	All numeric fields are ordered by little endian order.
*/
std::vector<uint8_t> InvalidCrcDone::pack_invalid_crc_done_request() const {
	std::vector<uint8_t> req = pack_header();

	std::copy(file_name, file_name + sizeof(file_name), req.begin() + REQUEST_HEADER_SIZE);

	return req;
}
