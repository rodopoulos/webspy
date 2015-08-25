/*
 * HTTP.cpp
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#include "HTTP.h"

namespace HTTP {

Message::Message(unsigned char* payload, std::size_t size){
	data = new char[size];
	memcpy(data, payload, size);
	parseHeaders();
	body = strstr(data, "\r\n\r\n") + 4;
}

Message::Message(Tins::IPv4Address srvAddr, uint16_t srvPort, unsigned char* payload, std::size_t size){
	this->srvAddr = srvAddr;
	this->srvPort = srvPort;
}

Message::~Message(){};

void Message::parseHeaders(){
	std::stringstream ss;
	char* ptr = strstr(data, "\r\n") + 2;
	ss << ptr;

	for(; ptr[0] != '\r'; ptr = strstr(ptr, "\r\n") + 2){
		std::string key;
		std::string value;
		getline(ss, key, ':');
		ss.ignore(); // ignore blank space
		getline(ss, value, '\r');
		ss.ignore(); // ignore new line
		headers[key] = value;
	}
}

std::size_t Message::dataSize(){
	std::size_t total = 0;
	std::size_t constant = 4; // : + ' ' + \r\n

	auto it = headers.begin();
	for(; it != headers.end(); it++){
		total = it->first.size() + it->second.size() + constant;
	}
	total += 2 + strlen(data);
	return total;
}

std::string Message::getHeader(std::string key){
	auto value = headers.find(key);
	if(value == headers.end())
		return ("");
	else
		return value->second;
}

bool Message::hasHeader(std::string key){
	auto value = headers.find(key);
	if(value == headers.end())
		return false;
	else
		return true;
}

void Message::stripHeader(std::string key){
	headers.erase(key);
}

void Message::alterHeader(std::string key, std::string value){
	headers[key] = value;
}

void Message::setServer(Tins::IPv4Address addr, uint16_t port){
	srvAddr = addr;
	srvPort = port;
}

void Message::setURI(std::string uri){
	this->uri = uri;
}

/******************************************************************************
 * * * * * * * * * * * * * * HTTP Request * * * * * * * * * * * * * * * * * * *
 *****************************************************************************/
Request::Request(unsigned char* payload, std::size_t size)
: Message(payload, size){
	std::stringstream ss;
	ss << data;
	ss >> method >> uri >> version;
}

Request::~Request(){}

const char* Request::flushData(){
	std::stringstream output;
	std::string endline("\r\n");
	output << method << ' ' << uri << ' '  << version << endline;
	for(auto it = headers.begin(); it != headers.end(); it++){
		output << it->first << ": " << it->second << endline;
	}
	output << endline;
	output << body;
	const std::string& tmp = output.str();
	const char* result = tmp.c_str();
	return result;
}

/******************************************************************************
 * * * * * * * * * * * * * * HTTP Response * * * * * * * * * * * * * * * * * *
 *****************************************************************************/
Response::Response(unsigned char* payload, std::size_t size)
: Message(payload, size){

	std::stringstream ss;
	ss << data;
	ss >> version >> code;
	ss.ignore();
	getline(ss, message, '\r');
}

Response::~Response(){}

const char* Response::flushData(){
	std::stringstream stream;
	std::string endline("\r\n");
	stream << version << ' ' << code << ' '  << message << endline;
	for(auto it = headers.begin(); it != headers.end(); it++){
		stream << it->first << ": " << it->second << endline;
	}
	stream << endline;
	stream << body;
	std::string tmp = stream.str();
	const char* result = tmp.c_str();
	return result;
}


} /* namespace HTTP */
