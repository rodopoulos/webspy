/*
 * Protocols.cpp
 *
 *  Created on: 21/05/2015
 *      Author: rodopoulos
 */

#include "Protocols.h"

// --------- ETHER HEADER METHODS ------------------------------------

Ethernet::Ethernet(unsigned char *buf){
	memcpy(&thaddr, buf, 6);
	buf = buf + 6;
	memcpy(&shaddr, buf, 6);
	buf = buf + 6;
	memcpy(&ptype, buf, 2);
}

uint16_t Ethernet::getType(){
	return htonl(this->ptype);
}

const char* Ethernet::getTypeName(){
	switch(htons(this->ptype)){
	case ETHERTYPE_ARP:
		return "ARP";
		break;
	case ETHERTYPE_IP:
		return "IP";
		break;
	case ETHERTYPE_IPV6:
		return "IPv6";
		break;
	case ETHERTYPE_LOOPBACK:
		return "Loopback";
		break;
	default:
		return "Other";
		break;
	}
}






// --------- ARP HEADER METHODS ------------------------------------

ARP::ARP(unsigned char* buf){
	buf += 14; // Jumping Ethernet Header
	memcpy(&htype, buf, 14);
	buf += 14; // Jumping ARP Header
	memcpy(&spaddr, buf, 10);
	buf += 10; // Jumping Sender MAC and IP
	memcpy(&tpaddr, buf, 4);
}

uint16_t ARP::getOperation(){
	return ntohl(this->arpOp);
}







// --------- IP HEADER METHODS ------------------------------------
IP::IP(unsigned char* buf){
	buf += 14;
	memcpy(&versionAndHl, buf, 20);
}

int IP::getHdrLen(){
	return (versionAndHl & 0xf) * 4;;
}






// --------- TCP HEADER METHODS ------------------------------------
TCP::TCP(unsigned char* buf){
	buf += 34;
	memcpy(&sport, buf, 20);
}

int TCP::getHdrLen(){
	return hlen >> 2;
}








// --------- HTTP METHODS ------------------------------------
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
