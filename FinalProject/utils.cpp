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

	uint16_t native_code = boost::endian::little_to_native(combined);
	return native_code;
}

uint32_t get_response_payload_size(std::vector<uint8_t> header) {
	uint8_t first = header[3], second = header[4];
	uint8_t third = header[5], last = header[6];

	uint32_t combined = (static_cast<uint32_t>(first) << 24) | (static_cast<uint32_t>(second) << 16) | (static_cast<uint32_t>(third) << 8) | last;

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

bool file_names_match(std::string response_file_name, char file_name[]) {
	std::string file_name_str(file_name);

	return response_file_name == file_name_str;
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

int getFileSize(std::string file_name) {
	std::string file_path = EXE_DIR_FILE_PATH(file_name);

	// Opening the file in binary mode and going to its end.
	std::ifstream file(file_path, std::ios::binary | std::ios::ate); 
	if (file.is_open()) {
		// Getting the position of the end of the file, meaning, its size.
		std::streampos size = file.tellg();  
		file.close();
		// Returning the size of the file in bytes.
		return static_cast<int>(size); 
	}

	// Returning -1 if the file did not open.
	return -1; 
}

std::string fileToString(std::string file_name) {
	std::string file_path = EXE_DIR_FILE_PATH(file_name);
	std::ifstream file(file_path, std::ios::binary);

	if (file.is_open()) {
		std::ostringstream oss;
		oss << file.rdbuf();
		file.close();
		return oss.str();
	}

	throw std::runtime_error("The client's file did not open, aborting program.");
}
