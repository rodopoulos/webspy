/*
 * Packet.cpp
 *
 *  Created on: 10 de jul de 2015
 *      Author: rodopoulos
 */

#include "Packet.h"

Packet::Packet(const unsigned char* data, int len) {
	this->len = len;
	this->data = (const unsigned char*) malloc(len * sizeof(const unsigned char*));
	memcpy((unsigned char*) this->data, data, len);
}

Packet::~Packet() {}

bool Packet::isHTTP(){
	IP* ip = (IP*) (14 + data);
	if(ip->protocol == IPPROTO_TCP){
		TCP* tcp = (TCP*) (14 + 20 + data);
		if(tcp->flags == 0x18){
			const char* payload = (const char*) this->getPayload();
			if(strstr(payload, "HTTP") != NULL){
				return true;
			}
		}
	}
	return false;
}

const unsigned char* Packet::getPayload(){
	TCP* tcp = (TCP*) (14 + 20 + data);
	return (14 + 20 + tcp->getHdrLen() + data);
}
