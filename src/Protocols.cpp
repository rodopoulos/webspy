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

// --------- HTTP HEADER METHODS ------------------------------------
HTTP::HTTP(unsigned char* buf, int size){
	memcpy(&data, buf, size);
	len = size;
}

