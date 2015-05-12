/*
 * MACAddress.cpp
 *
 *  Created on: May 8, 2015
 *      Author: Felipe Rodopoulos
 */

#include <cstdio>

#include "MACAddress.h"

using namespace std;

MACAddress::MACAddress() { }

MACAddress::~MACAddress() { }

MACAddress::MACAddress(std::string mac){
	char* tmp = (char*)mac.c_str();
	uint8_t octs[4];

	sscanf(tmp, "%x:%x:%x:%x:%x:%x", octs[0], octs[1], octs[2], octs[3], octs[4], octs[5]);

	this->mac = (octs[0] << 40) +
				(octs[1] << 32) +
				(octs[2] << 24) +
				(octs[3] << 16) +
				(octs[4] << 8) +
				octs[5];
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
