#include "utils.hpp"

int main() {
	boost::uuids::uuid uuid = boost::uuids::nil_uuid();
	std::cout << sizeof(uuid) << std::endl;

	char id[16] = {};


	/*for (int i = 0; i < 16; i++) {
		id[i] = (uid[i * 2] * 16) + uid[i * 2 + 1];
	}*/

	std::memcpy(id, uuid.data, 16);

	/*for (int i = 0; i < 16; i++) {
		std::cout << id[i];
	}*/
	// std::cout << std::endl;

	// std::cout << uid << std::endl;

	for (int i = 0; i < 16; i++) {
		if (id[i] != uuid.data[i]) {
			std::cout << "false" << std::endl;
		}
		std::cout << (id[i] == 0) << (uuid.data[i] == 0) << std::endl;
	}

	for (int i = 0; i < 16; i++) {
		std::cout << static_cast<int>(uuid.data[i]) << " ";
	}
	std::cout << std::endl;

	return 0;
}