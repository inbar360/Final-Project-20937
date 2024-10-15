#include "client.hpp"


Client::Client() {
	this->address = "";
	this->port = "";
	this->name = "";
	this->file_path = "";
	this->uuid = NIL_UUID;
}

void Client::setAddress(std::string address) {
	this->address = address;
}

void Client::setPort(std::string port) {
	this->port = port;
}

void Client::setName(std::string name) {
	this->name = name;
}

void Client::setFilePath(std::string file_path) {
	this->file_path = file_path;
}

void Client::setUuid(UUID uuid) {
	this->uuid = uuid;
}

std::string Client::getAddress() const {
	return this->address;
}

std::string Client::getPort() const {
	return this->port;
}

std::string Client::getName() const {
	return this->name;
}

std::string Client::getFilePath() const {
	return this->file_path;
}

UUID Client::getUuid() const {
	return this->uuid;
}