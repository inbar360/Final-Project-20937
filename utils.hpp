#ifndef UTILS_H
#define UTILS_H

#include <iostream>
#include <fstream>
#include <string>
#include <boost/asio.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/nil_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/endian/conversion.hpp>
#include <filesystem>
#include <string.h>
#include "RSAWrapper.h"
#include "Base64Wrapper.h"

using boost::asio::ip::tcp;
using UUID = boost::uuids::uuid;

const std::string EXE_DIR = "client.cpp\\..\\..\\x64\\debug";
#define EXE_DIR_FILE_PATH(file_name) (EXE_DIR + "\\" + file_name)
#define NIL_UUID boost::uuids::nil_uuid()
constexpr auto VERSION = 3;
constexpr auto NAME_LENGTH = 255;
constexpr auto PUBLIC_KEY_LENGTH = 160;
constexpr auto REQUEST_HEADER_SIZE = 23;
constexpr auto RESPONSE_HEADER_SIZE = 7;
#define FATAL_MESSAGE_RETURN(type) \
	cerr << "Fatal: " << type << " request failed.\n"; \
	return;

bool is_integer(const std::string& s);
int response_payload_sizes(int response_code);
uint16_t get_response_code(std::vector<uint8_t> header);
uint32_t get_response_payload_size(std::vector<uint8_t> header);
bool id_vectors_match(std::vector<uint8_t> first, UUID second);
UUID getUuidFromString(std::string client_id);

enum PayloadSize: uint32_t {
	REGISTRATION_P = 255,
	SENDING_PUBLIC_KEY_P = 415,
	RECONNECTION_P = 255,
	SENDING_FILE_P = 343,
	VALID_CRC_P = 255,
	SENDING_CRC_AGAIN_P = 255,
	INVALID_CRC_DONE_P = 255,

	REGISTRATION_SUCCEEDED_P = 16,
	REGISTRATION_FAILED_P = 0,
	PUBLIC_KEY_RECEIVED_P = 176,
	FILE_RECEIVED_CRC_P = 279,
	MESSAGE_RECEIVED_P = 16,
	RECONNECTION_SUCCEEDED_P = 176,
	RECONNECTION_FAILED_P = 16,
	GENERAL_ERROR_P = 0
};

enum Codes: uint16_t {
	REGISTRATION_C = 825,
	SENDING_PUBLIC_KEY_C = 826,
	RECONNECTION_C = 827,
	SENDING_FILE_C = 828,
	VALID_CRC_C = 900,
	SENDING_CRC_AGAIN_C = 901,
	INVALID_CRC_DONE_C = 902,

	REGISTRATION_SUCCEEDED_C = 1600,
	REGISTRATION_FAILED_C = 1601,
	PUBLIC_KEY_RECEIVED_C = 1602,
	FILE_RECEIVED_CRC_C = 1603,
	MESSAGE_RECEIVED_C = 1604,
	RECONNECTION_SUCCEEDED_C = 1605,
	RECONNECTION_FAILED_C = 1606,
	GENERAL_ERROR_C = 1607
};

#endif