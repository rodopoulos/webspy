/*
 * Packet.cpp
 *
 *  Created on: 10 de jul de 2015
 *      Author: rodopoulos
 */

#include "Packet.h"

/************************************************************************
 * * * * * * * * CONSTRUCTORS * * * * * * * * * * * * * * * * * * * * * *
 ************************************************************************/
Packet::Packet(const unsigned char* data, int len) {
	this->len = len;
	this->data = new unsigned char[len];
	memcpy(this->data, data, len);

	ethernet = (Ethernet*) this->data;
	ip = (IP*) (14 + this->data);
	if(ip->protocol == IPPROTO_TCP)
		tcp = (TCP*) (14 + ip->getHdrLen() + this->data);
}

Packet::~Packet() {}




/******************************************************************************
 * * * * * * * * PACKET LAYERS * * * * * * * * * * * * * * * * * * * * * * * **
 *****************************************************************************/
/*Ethernet* Packet::getEthernet(){
	return (Ethernet*) data;
}

IP* Packet::getIP(){
	return (IP*) (14 + data);
}*/

TCP* Packet::getTCP(){
	return (TCP*) (14 + this->ip->getHdrLen() + data);
}

unsigned char* Packet::getPayload(){
	TCP* tcp = (TCP*) (14 + 20 + data);
	return 14 + ip->getHdrLen() + tcp->getHdrLen() + data;
}




/************************************************************************
 * * * * * * * * UTILS * * * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
int Packet::getHdrLen(){
	return 14 + ip->getHdrLen() + getTCP()->getHdrLen();
}

int Packet::getPayloadLen(){
	return len - getHdrLen();
}

bool Packet::isTCPSegment(){
	if(ip->protocol == IPPROTO_TCP){
		if(getTCP()->flags != 0x18){
			const char* payload = (const char*) this->getPayload();
			if(strstr(payload, "HTTP") != NULL){
				return true;
			}
		}
	}
	return false;
}

bool Packet::isHTTP(){
	if(ip->protocol == IPPROTO_TCP && getTCP()->flags == 0x18){
		const char* payload = (const char*) this->getPayload();
		if(strstr(payload, "HTTP/1.0")||
		   strstr(payload, "HTTP/1.1")||
		   strstr(payload, "HTTP/2.0")){
			if(len > 1514)
				return true;
			if (strstr(payload, "GET") || strstr(payload, "POST"))
				return true;
		}
	}
	return false;
}

void Packet::printPayload(){
	printf("\n-------------------- CONTENT --------------------\n");
	printf("\n%s\n", getPayload());
}
