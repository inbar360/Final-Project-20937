#include "utils.hpp"

bool is_integer(const std::string& num) {
	std::string::const_iterator iterator = num.begin();
	while (iterator != num.end() && std::isdigit(*iterator)) {
		iterator++;
	}

	return !num.empty() && iterator == num.end();
}

uint16_t get_response_code(std::vector<uint8_t> header) {
	uint8_t high = header[1], low = header[2];
	uint16_t combined = (static_cast<uint16_t>(high) << 8) | low;

	/*
		This, in my opinion, isn't quite intuitive so I'll explain it a little:
		By the way I define the 'combined' variable, I only insert it's value, meaning,
		if the operating system operates by little-endian order, it'll reverse the bytes.
		That being said, the value received is already in little-endian so we'll need to reverse them back.
	*/
	if (boost::endian::order::native == boost::endian::order::little) {
		return boost::endian::endian_reverse(combined);
	}

	return combined;
}

uint32_t get_response_payload_size(std::vector<uint8_t> header) {
	uint8_t first = header[3], second = header[4];
	uint8_t third = header[5], last = header[6];

	uint32_t combined = (static_cast<uint32_t>(first) << 24) |
						(static_cast<uint32_t>(second) << 16) |
						(static_cast<uint32_t>(third) << 8) |
						(static_cast<uint32_t>(last));

	/*
		This, in my opinion, isn't quite intuitive so I'll explain it a little:
		By the way I define the 'combined' variable, I only insert it's value, meaning, 
		if the operating system operates by little-endian order, it'll reverse the bytes.
		That being said, the value received is already in little-endian so we'll need to reverse them back.
	*/
	if (boost::endian::order::native == boost::endian::order::little) {
		return boost::endian::endian_reverse(combined);
	}

	return combined;
}

bool id_vectors_match(std::vector<uint8_t> first, UUID second) {
	for (int i = 0; i < first.size(); i++) {
		if (first[i] != second.data[i])
			return false;
	}

	return true;
}

bool file_names_match(std::string response_file_name, char file_name[], size_t file_length) {
	std::string file_name_str(file_name, file_name + file_length);

	return (response_file_name == file_name_str);
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

std::string fileToCharArray(std::string file_name) {
	std::string file_path = EXE_DIR_FILE_PATH(file_name);
	if (std::filesystem::exists(file_path)) {
		std::ifstream f1(file_path.c_str(), std::ios::binary);

		size_t size = std::filesystem::file_size(file_path);
		char* b = new char[size];
		f1.seekg(0, std::ios::beg);
		f1.read(b, size);

		std::string con(b, b + size);

		delete[] b;
		f1.close();
		return con;
	}
	else {
		throw std::runtime_error("Cannot open input file " + file_path + ".");
	}
}
