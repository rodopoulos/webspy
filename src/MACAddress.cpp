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

MACAddress::MACAddress(std::string mac){
	char* tmp = (char*)mac.c_str();
	uint32_t octs[6];

	sscanf(tmp, "%x:%x:%x:%x:%x:%x", &octs[0], &octs[1], &octs[2], &octs[3], &octs[4], &octs[5]);

	this->mac = (uint64_t(octs[0]) << 40) +
				(uint64_t(octs[0]) << 32) +
				(uint64_t(octs[0]) << 24) +
				(uint64_t(octs[0]) << 16) +
				(uint64_t(octs[0]) << 8) +
				uint64_t(octs[0]);
}

MACAddress::MACAddress(uint64_t mac) : mac(mac) {}

string MACAddress::toString(){
	char tmp[16];
	sprintf(tmp, "%x:%x:%x:%x:%x:%x",
			int(((uint8_t*)&mac)[0]),
			int(((uint8_t*)&mac)[1]),
			int(((uint8_t*)&mac)[2]),
			int(((uint8_t*)&mac)[3]),
			int(((uint8_t*)&mac)[4]),
			int(((uint8_t*)&mac)[5])
	);
	return string(tmp);
}
