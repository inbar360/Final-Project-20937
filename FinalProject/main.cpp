#include "client.hpp"
#include "request.hpp"

// This method checks if the data read from 'transfer.info' is valid.
static bool validTransfer(Client &client, std::string ip_port, std::string name, std::string file_path) {
	size_t pos = ip_port.find(':');

	if (pos == std::string::npos || name.length() > MAX_NAME_LENGTH || name.length() == 0 || file_path.length() == 0) {
		return false;
	}

	// Save the ip and port numbers into different parameters.
	std::string ip = ip_port.substr(0, pos);
	std::string port = ip_port.substr(pos + 1);

	// Check if the port is a valid integer.
	bool valid = is_integer(port);
	if (!valid) {
		return false;
	}

	// Set the client's attributes.
	client.setAddress(ip);
	client.setPort(port);
	client.setName(name);
	client.setFilePath(file_path);
	// Return true.
	return true;
}

// This method creates the client, reads from the transfer.info file and sets the client's attributes.
static Client createClient() {
	std::string transfer_path = EXE_DIR_FILE_PATH("transfer.info");
	std::string line, ip_port, client_name, client_file_path;
	std::ifstream transfer_file(transfer_path);
	int lines = 1;
	Client client;

	if (!transfer_file.is_open()) {
		throw std::runtime_error("Error opening the 'transfer.info' file, aborting program.");
	}

	// Read from transfer.info file into parameters.
	while (getline(transfer_file, line)) {
		std::cout << "'" << line << "' " << line.length() << std::endl;
		switch (lines) {
			case 1:
				ip_port = line;
				break;
			case 2:
				client_name = line;
				break;
			case 3:
				client_file_path = line;
				break;
			default:
				break;
		}
		lines++;
	}
	
	if (lines != 4) {
		throw std::invalid_argument("Error: transfer.info file contains invalid data.");
	}

	if (!validTransfer(client, ip_port, client_name, client_file_path)) {
		throw std::invalid_argument("Error: transfer.info file contains invalid data.");
	}

	// Close the file and return the client.
	transfer_file.close();
	return client;
}

// This method is used for reading the name, id, and private key from the me.info and priv.key files.
static std::string read_from_files(Client& client) {
	std::string path_info = EXE_DIR_FILE_PATH("me.info");
	std::string path_key = EXE_DIR_FILE_PATH("priv.key");
	std::string line, client_name, client_id, private_key_me, private_key_priv;
	int lines = 1;
	std::ifstream info_file(path_info), key_file(path_key);

	if (!info_file.is_open()) {
		throw std::runtime_error("Error opening the 'me.info' file, aborting program.");
	}
	if (!key_file.is_open()) {
		throw std::runtime_error("Error opening the 'priv.key' file, aborting program.");
	}

	// Read from me.info file into parameters.
	while (std::getline(info_file, line)) {
		switch (lines) {
			case 1:
				client_name = line;
				break;
			case 2:
				client_id = line;
				break;
			case 3:
				private_key_me = line;
				break;
			default:
				private_key_me += line;
				break;
		}
		lines++;
	}

	if (client_name.length() > MAX_NAME_LENGTH || client_name.length() == 0 || client_id.length() != HEX_ID_LENGTH || private_key_me.length() == 0) {
		throw std::invalid_argument("Error: me.info file contains invalid data.");
	}

	// Read from priv.key file into parameters.
	while (std::getline(key_file, line)) {
		if (lines == 1) {
			private_key_priv = line;
		}
		else {
			private_key_priv += line;
		}
		lines++;
	}

	if (private_key_priv.length() == 0 || private_key_priv != private_key_me) {
		throw std::invalid_argument("Error: priv.key file contains invalid data.");
	}

	// Get id in form of boost::uuids::uuid and set the client's name and uuid.
	UUID id = getUuidFromString(client_id);
	client.setName(client_name);
	client.setUuid(id);

	// Close the file and return the private key (encoded in base64).
	info_file.close();
	return private_key_me;
}

// This method receives the client's name, id, and private key, writes them to me.info and writes the private key to priv.key as well.
static void save_to_files(std::string name, UUID uuid, std::string priv_key) {
	// Saving id and key into wanted formats, saving paths for both files and opening the streams.
	std::string id = boost::uuids::to_string(uuid);
	id.erase(std::remove(id.begin(), id.end(), '-'), id.end()); // Remove '-' from the string.

	// Encode the private key to base64 and open files.
	std::string base64PrivKey = Base64Wrapper::encode(priv_key);
	std::string path_info = EXE_DIR_FILE_PATH("me.info");
	std::string path_key = EXE_DIR_FILE_PATH("priv.key");
	std::ofstream info_file(path_info), key_file(path_key);

	if (!info_file.is_open()) {
		throw std::runtime_error("Error opening the 'me.info' file, aborting program.");
	}
	if (!key_file.is_open()) {
		throw std::runtime_error("Error opening the 'priv.key' file, aborting program.");
	}

	// Writing to both files.
	info_file << name << std::endl << id << std::endl << base64PrivKey << std::endl;
	key_file << base64PrivKey << std::endl;
	// Closing the streams.
	info_file.close();
	key_file.close();
}

// This method runs the client's program - sends it's requests and gets responses.
static void run_client(tcp::socket &sock, Client& client) {
	int op_success;
	std::string private_key, decrypted_aes_key;

	// If me.info does not exist, send Registration request.
	if (!std::filesystem::exists(EXE_DIR_FILE_PATH("me.info"))) {
		Registration registration(client.getUuid(), Codes::REGISTRATION_C, PayloadSize::REGISTRATION_P, client.getName().c_str());
		op_success = registration.run(sock);

		if (op_success == FAILURE) {
			FATAL_MESSAGE_RETURN("Registration");
		}

		// Set client's new UUID.
		client.setUuid(registration.getUuid());
		// Create RSA pair, save fields data into me.info and prev.key files, and send a SendingPublicKey request.
		RSAPrivateWrapper prevKeyWrapper;
		std::string public_key = prevKeyWrapper.getPublicKey();

		private_key = prevKeyWrapper.getPrivateKey();
		save_to_files(client.getName(), client.getUuid(), private_key);
		SendingPublicKey sending_pub_key(client.getUuid(), Codes::SENDING_PUBLIC_KEY_C, PayloadSize::SENDING_PUBLIC_KEY_P, client.getName().c_str(), public_key);
		op_success = sending_pub_key.run(sock);

		if (op_success == FAILURE) {
			FATAL_MESSAGE_RETURN("Sending Public Key");
		}

		// Get the encrypted AES key and decrypt it.
		std::string encrypted_aes_key = sending_pub_key.getEncryptedAesKey();
		decrypted_aes_key = prevKeyWrapper.decrypt(encrypted_aes_key);
	}
	else { // If me.info does exist, read id and send reconnection request.
		// Read the fields from the client.
		std::string key_base64 = read_from_files(client);

		// Send Reconnection request to the server.
		Reconnection reconnection(client.getUuid(), Codes::RECONNECTION_C, PayloadSize::RECONNECTION_P, client.getName().c_str());
		op_success = reconnection.run(sock);

		if (op_success == FAILURE) { // Request failed.
			FATAL_MESSAGE_RETURN("Reconnection");
		}
		else if (op_success == SPECIAL) { // Registration succeded instead of Reconnection.
			// Set client's new UUID.
			client.setUuid(reconnection.getUuid());
			// Create RSA pair, save fields data into me.info and prev.key files, and send a SendingPublicKey request.
			RSAPrivateWrapper prevKeyWrapper;
			std::string public_key = prevKeyWrapper.getPublicKey();
			private_key = prevKeyWrapper.getPrivateKey();
			save_to_files(client.getName(), client.getUuid(), private_key);
			SendingPublicKey sending_pub_key(client.getUuid(), Codes::SENDING_PUBLIC_KEY_C, PayloadSize::SENDING_PUBLIC_KEY_P, client.getName().c_str(), public_key);
			op_success = sending_pub_key.run(sock);

			if (op_success == FAILURE) {
				FATAL_MESSAGE_RETURN("Sending Public Key");
			}

			// Get the encrypted AES key and decrypt it.
			std::string encrypted_aes_key = sending_pub_key.getEncryptedAesKey();
			decrypted_aes_key = prevKeyWrapper.decrypt(encrypted_aes_key);
		}
		else { // Reconnection succeeded.
			// Decode the private key and create the decryptor.
			private_key = Base64Wrapper::decode(key_base64);
			RSAPrivateWrapper prevKeyWrapper(private_key);

			// Get the encrypted AES key and decrypt it.
			std::string encrypted_aes_key = reconnection.getEncryptedAesKey();
			decrypted_aes_key = prevKeyWrapper.decrypt(encrypted_aes_key);
		}
	}

	AESWrapper aesKeyWrapper(reinterpret_cast<const unsigned char *>(decrypted_aes_key.c_str()), static_cast<unsigned int>(decrypted_aes_key.size()));
	int file_error_cnt = 0, times_crc_sent = 0;
	while (file_error_cnt != MAX_REQUEST_FAILS && times_crc_sent != MAX_INVALID_CRC) {
		// Get the file's content, save the encrypted content and save the sizes of both.
		std::string content = fileToCharArray(client.getFilePath());
		std::string encrypted_content = aesKeyWrapper.encrypt(content.c_str(), static_cast<unsigned int>(content.size()));
		uint32_t content_size = static_cast<uint32_t>(encrypted_content.length());
		uint32_t orig_size = static_cast<uint32_t>(content.size());

		// Save the total packets and send the Sending File request to the server.
		uint16_t total_packs = TOTAL_PACKETS(content_size);

		SendingFile sendingFile(client.getUuid(), Codes::SENDING_FILE_C, PayloadSize::SENDING_FILE_P, content_size, orig_size, total_packs, client.getFilePath().c_str(), encrypted_content);
		op_success = sendingFile.run(sock);
		// If the sending file request did not succeed, add 1 to sending file error counter and continue the loop.
		if (op_success == FAILURE) {
			file_error_cnt++;
			continue;
		}

		// Get the cksum the server responded with.
		unsigned long response_cksum = sendingFile.getCksum();
		std::cout << "readfile func returns - " << readfile(EXE_DIR_FILE_PATH(client.getFilePath())) << std::endl;
		unsigned long request_cksum = memcrc(content.c_str(), orig_size);

		if (response_cksum == request_cksum) {
			std::cout << "wohoo they're the same!\n";
			break;
		}
		
		// If the crc given by the server is incorrect, send Sending Crc Again request - 901.
		SendingCrcAgain sendingCrcAgain(client.getUuid(), Codes::SENDING_CRC_AGAIN_C, PayloadSize::SENDING_CRC_AGAIN_P, client.getFilePath().c_str());
		sendingCrcAgain.run(sock);
		
		// If the sending crc request did not succeed, add 1 to times crc sent counter.
		times_crc_sent++;
	}
	if (file_error_cnt == MAX_REQUEST_FAILS) { // If the Sending File request failed three times print fatal and return.
		FATAL_MESSAGE_RETURN("Sending File");
	}
	else if (times_crc_sent == MAX_INVALID_CRC) { // If the CRC was invalid three times,
		InvalidCrcDone invalid_crc_done(client.getUuid(), Codes::INVALID_CRC_DONE_C, PayloadSize::INVALID_CRC_DONE_P, client.getFilePath().c_str());
		op_success = invalid_crc_done.run(sock);

		if (op_success == FAILURE) {
			FATAL_MESSAGE_RETURN("Invalid CRC for the fourth time");
		}
	}
	else {
		ValidCrc valid_crc(client.getUuid(), Codes::VALID_CRC_C, PayloadSize::VALID_CRC_P, client.getFilePath().c_str());
		op_success = valid_crc.run(sock);

		if (op_success == FAILURE) {
			FATAL_MESSAGE_RETURN("Valid CRC");
		}
	}
	std::cout << "done!\n";
}

int main() {

	try {
		Client client = createClient();

		boost::asio::io_context io_context;
		tcp::socket sock(io_context);
		tcp::resolver resolver(io_context);
		boost::asio::connect(sock, resolver.resolve(client.getAddress(), client.getPort()));

		run_client(sock, client);
	}
	catch (std::exception& e) {
		std::cerr << e.what() << std::endl;
	}

	return 0;
}