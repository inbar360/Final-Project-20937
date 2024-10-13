#include "client.hpp"
#include "request.hpp"

using namespace std;

static bool validTransfer(Client &client, string ip_port, string name, string file_path) {
	size_t pos = ip_port.find(':');

	if (pos == string::npos || name.length() > 100 || name.length() == 0 || file_path.length() == 0) {
		return false;
	}

	string ip = ip_port.substr(0, pos);
	string port = ip_port.substr(pos + 1);

	bool valid = is_integer(port);
	if (!valid) {
		return false;
	}

	client.setAddress(ip);
	client.setPort(port);
	client.setName(name);
	client.setFilePath(file_path);

	return true;
}

static Client createClient() {
	string transfer_path = EXE_DIR_FILE_PATH("transfer.info.txt");
	string line, ip_port, client_name, client_file_path;
	ifstream transfer_file(transfer_path);
	int lines = 1, invalid_file_data = 0;
	Client client;

	if (!transfer_file.is_open()) {
		throw std::runtime_error("Error opening the 'transfer.info' file, aborting program.");
	}

	while (getline(transfer_file, line)) {
		cout << "'" << line << "' " << line.length() << endl;
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

	transfer_file.close();
	return client;

}

static string read_from_me_info(Client& client) {
	string path_info = EXE_DIR_FILE_PATH("me.info.txt");
	string line, client_name, client_id, private_key;
	int lines = 1;
	ifstream info_file(path_info);

	if (!info_file.is_open()) {
		throw std::runtime_error("Error opening the 'me.info' file, aborting program.");
	}

	while (getline(info_file, line)) {
		cout << "'" << line << "' " << line.length() << endl;
		switch (lines) {
		case 1:
			client_name = line;
			break;
		case 2:
			client_id = line;
			break;
		case 3:
			private_key = line;
			break;
		default:
			break;
		}
		lines++;
	}

	if (lines != 4 || client_name.length() > 100 || client_name.length() == 0 || client_id.length() != 32 || private_key.length() == 0) {
		throw std::invalid_argument("Error: me.info file contains invalid data.");
	}
	// Get id in form of boost::uuids::uuid and set the client's name and uuid.
	UUID id = getUuidFromString(client_id);
	client.setName(client_name);
	client.setUuid(id); 

	// Close the file and return the private key (encoded in base64).
	info_file.close();
	return private_key;
}

// This method receives the client's name, id, and private key, writes them to me.info and writes the private key to priv.key as well.
static void save_to_files(string name, UUID uuid, string priv_key) {
	// Saving id and key into wanted formats, saving paths for both files and opening the streams.
	string id = boost::uuids::to_string(uuid);
	id.erase(remove(id.begin(), id.end(), '-'), id.end()); // Remove '-' from the string.

	string base64PrivKey = Base64Wrapper::encode(priv_key);
	string path_info = EXE_DIR_FILE_PATH("me.info.txt");
	string path_key = EXE_DIR_FILE_PATH("priv.key.txt");
	ofstream info_file(path_info), key_file(path_key);

	if (!info_file.is_open()) {
		throw std::runtime_error("Error opening the 'me.info' file, aborting program.");
	}
	if (!key_file.is_open()) {
		throw std::runtime_error("Error opening the 'priv.key' file, aborting program.");
	}

	// Writing to both files.
	info_file << name << endl << id << endl << base64PrivKey << endl;
	key_file << base64PrivKey << endl;
	// Closing the streams.
	info_file.close();
	key_file.close();
}

static void run_client(tcp::socket &sock, Client& client) {
	bool op_success;
	string private_key, decrypted_aes_key;

	// If me.info does not exist, send Registration request.
	if (!filesystem::exists(EXE_DIR_FILE_PATH("me.info.txt"))) {
		Registration registration(client.getUuid(), Codes::REGISTRATION_C, PayloadSize::REGISTRATION_P, client.getName().c_str());
		op_success = registration.run(sock);

		if (!op_success) {
			FATAL_MESSAGE_RETURN("Registration");
		}
		// Create RSA pair, save fields data into me.info and prev.key files, and send a SendingPublicKey request.
		RSAPrivateWrapper prevKeyWrapper;
		string public_key = prevKeyWrapper.getPublicKey();
		private_key = prevKeyWrapper.getPrivateKey();
		save_to_files(client.getName(), client.getUuid(), private_key);
		SendingPublicKey sending_pub_key(client.getUuid(), Codes::SENDING_PUBLIC_KEY_C, PayloadSize::SENDING_PUBLIC_KEY_P, client.getName().c_str(), public_key.c_str());
		op_success = sending_pub_key.run(sock);

		if (!op_success) {
			FATAL_MESSAGE_RETURN("Sending Public Key");
		}

		// Get the encrypted AES key and decrypt it.
		string encrypted_aes_key = sending_pub_key.getEncryptedAesKey();
		decrypted_aes_key = prevKeyWrapper.decrypt(encrypted_aes_key);
	}
	else { // If me.info does exist, read id and send reconnection request.
		// Read the fields from the client.
		string key_base64 = read_from_me_info(client);

		// Send Reconnection request to the server.
		Reconnection reconnection(client.getUuid(), Codes::RECONNECTION_C, PayloadSize::RECONNECTION_P, client.getName().c_str());
		op_success = reconnection.run(sock);

		if (!op_success) {
			FATAL_MESSAGE_RETURN("Reconnection");
		}

		// Decode the private key and create the decryptor.
		private_key = Base64Wrapper::decode(key_base64);
		RSAPrivateWrapper prevKeyWrapper(private_key);

		// Get the encrypted AES key and decrypt it.
		string encrypted_aes_key = reconnection.getEncryptedAesKey();
		decrypted_aes_key = prevKeyWrapper.decrypt(encrypted_aes_key);
	}
}

/* int main() {

	Client client = createClient();

	boost::asio::io_context io_context;
	tcp::socket sock(io_context);
	tcp::resolver resolver(io_context);
	boost::asio::connect(sock, resolver.resolve(client.getAddress(), client.getPort()));

	run_client(sock, client);

	return 0;
} */