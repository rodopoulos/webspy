/*
 * MACAddress.cpp
 *
 *  Created on: May 8, 2015
 *      Author: Felipe Rodopoulos
 */

#include <cstdio>

#include "MACAddress.h"

using namespace std;

MACAddress::MACAddress() : mac(0) { }

MACAddress::~MACAddress() { }

MACAddress::MACAddress(std::string macStr){
	char* tmp = (char*)macStr.c_str();
	uint32_t octs[6];

	sscanf(tmp, "%x:%x:%x:%x:%x:%x", &octs[0], &octs[1], &octs[2], &octs[3], &octs[4], &octs[5]);

	this->mac->ether_addr_octet[0] = uint8_t(octs[0]);
	this->mac->ether_addr_octet[1] = uint8_t(octs[1]);
	this->mac->ether_addr_octet[2] = uint8_t(octs[2]);
	this->mac->ether_addr_octet[3] = uint8_t(octs[3]);
	this->mac->ether_addr_octet[4] = uint8_t(octs[4]);
	this->mac->ether_addr_octet[5] = uint8_t(octs[5]);
}

MACAddress::MACAddress(libnet_ether_addr* mac) : mac(mac) {
	if(mac == NULL){
		fprintf(stderr, "webspy: [ERRO] Libnet erro: %s", libnet_geterror(WebSpyGlobals::context));
		exit(EXIT_FAILURE);
	}
}

void MACAddress::setMACAddress(libnet_ether_addr* mac){
	this->mac = mac;
}

libnet_ether_addr* MACAddress::getMACAddress(){
	return this->mac;
}

string MACAddress::toString(){
	char tmp[16];
	sprintf(tmp, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			this->mac->ether_addr_octet[0],
			this->mac->ether_addr_octet[1],
			this->mac->ether_addr_octet[2],
			this->mac->ether_addr_octet[3],
			this->mac->ether_addr_octet[4],
			this->mac->ether_addr_octet[5]
	);
	return string(tmp);
}
