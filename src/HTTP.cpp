/*
 * HTTP.cpp
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#include "HTTP.h"

HTTP::HTTP(uint32_t srvAddr, uint16_t srvPort, unsigned char* payload){
	this->srvAddr = srvAddr;
	this->srvPort = srvPort;

	this->host 	  = retrieveHeaderValue(payload, "Host");
	this->referer = retrieveHeaderValue(payload, "Referer");
	this->path 	  = retrieveObjectPath(payload);
}

int HTTP::readMethod(char* payload){
	if(strstr(payload, "GET")  ||
	   strstr(payload, "POST") ||
	   strstr(payload, "HEAD") ||
	   strstr(payload, "PUT")  ||
	   strstr(payload, "DELETE")
	){
		return HTTP_REQ;
	} else{
		return HTTP_RES;
	}
}

std::string HTTP::retrieveHeaderValue(unsigned char* payload, char* key){
	char* line = strstr((char*)payload, key);
	if(line){
		std::string value;
		std::stringstream ss;
		ss << line;
		ss >> value;
		ss >> value;
		return value;
	}
	return nullptr;
}

std::string HTTP::retrieveObjectPath(unsigned char* payload){
	char* line = strstr((char*)payload, "\r\n");
	std::string value;
	std::stringstream ss;
	ss << line;
	ss >> value;
	ss >> value;
	return value;
}

int HTTP::getContentTypeCode(std::string type){
	return 0;
}

void HTTP::setResponseContent(unsigned char* content, int len){
	data = new char[len];
	memcpy(data, content,len);
}
