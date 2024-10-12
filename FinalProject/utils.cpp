#include "utils.hpp"

bool is_integer(const std::string& num) {
	std::string::const_iterator iterator = num.begin();
	while (iterator != num.end() && std::isdigit(*iterator)) {
		iterator++;
	}

	return !num.empty() && iterator == num.end();
}

int response_payload_sizes(int response_code) {
	switch (response_code) {
		case 1601: case 1607: 
			return 0;
		case 1600: case 1604: case 1606:
			return 16;
		case 1602: case 1605:
			return 160; // Need to check if this is correct!
		case 1603:
			return 279;
		default:
			return 0;
	}
}

uint16_t get_response_code(std::vector<uint8_t> header) {
	uint8_t high = header[1], low = header[2];
	uint16_t combined = (static_cast<uint16_t>(high) << 8) | low;

	uint16_t native_code = boost::endian::little_to_native(combined);
	return native_code;
}

uint32_t get_response_payload_size(std::vector<uint8_t> header) {
	uint8_t first = header[3], second = header[4];
	uint8_t third = header[5], last = header[6];

	uint32_t combined = (static_cast<uint16_t>(first) << 24) | (static_cast<uint16_t>(second) << 16) | (static_cast<uint16_t>(third) << 8) | last;

	uint32_t native_code = boost::endian::little_to_native(combined);
	return native_code;
}

bool id_vectors_match(std::vector<uint8_t> first, UUID second) {
	for (int i = 0; i < first.size(); i++) {
		if (first[i] != second.data[i])
			return false;
	}

	return true;
}

UUID getUuidFromString(std::string client_id) {
	std::istringstream iss(client_id); // Not really necessary but I thought it was cooler than going over the string itself.
	UUID id;

	for (int i = 0; i < sizeof(id); i++) {
		char c1, c2;
		iss >> c1 >> c2; // Get two characters from stream.

		if (!((c1 >= '0' && c1 <= '9') || (c1 <= 'f' && c1 >= 'a')) || !((c2 >= '0' && c2 <= '9') || (c2 <= 'f' && c2 >= 'a'))) {
			throw std::invalid_argument("Error: me.info file contains invalid data.");
		}
		// Get their hex value.
		int x = (c1 <= '9' && c1 >= '0') ? (c1 - '0') : (c1 - 'a' + 10);
		int y = (c2 <= '9' && c2 >= '0') ? (c2 - '0') : (c2 - 'a' + 10);
		id.data[i] = (x * 16) + y; // Change the uuid data at index i to the 8 bit value.
	}

	return id;
}
