/*
 * HTTPSession.cpp
 *
 *  Created on: 8 de ago de 2015
 *      Author: rodopoulos
 */

#include "HTTPSession.h"

HTTPSession::HTTPSession(HTTP* http) {
	this->port = http->srvPort;
	this->addr = http->srvAddr;
	this->hostUrl = http->host;
	this->complete = false;
}

HTTPSession::~HTTPSession() {
	// TODO Auto-generated destructor stub
}

void HTTPSession::newRequest(HTTP* request){
	objects.push_back(request);
}

void HTTPSession::addRequestResponse(uint32_t addr, uint16_t port, int len, unsigned char* response){
	std::vector<HTTP*>::iterator it;
	for(it = objects.begin(); it != objects.end(); ++it){
		if((*it)->srvAddr == addr && (*it)->srvPort == port){
			std::string type = HTTP::retrieveHeaderValue(response, "Content-Type");
			if(HTTP::getContentTypeCode(type) == (*it)->contentType){

			}
		} else
			continue;
	}
}
