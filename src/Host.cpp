/*
 * Host.cpp
 *
 *  Created on: 15/04/2015
 *      Author: root
 */

// this
#include "Host.h"

// std
#include <iostream>

using namespace std;

int Host::currentID = 0;

// Constructors ------------------------------------------------------------------------

Host::Host() : ip(0), mac(NULL), name("") {
	this->id = currentID;
	currentID++;
}

Host::Host(uint32_t ip, libnet_ether_addr* mac, string name) : ip(ip), mac(mac), name(name){
	this->id = currentID;
	currentID++;
}

Host::~Host() {}

// Getters e Setters --------------------------------------------------------------------

void Host::setIP(uint32_t ip){
	this->ip = ip;
}

void Host::setMAC(libnet_ether_addr* mac){
	this->mac = mac;
}

void Host::setName(string name){
	this->name = name;
}

libnet_ether_addr* Host::getMAC(){
	return this->mac;
}

uint32_t Host::getIP(){
	return this->ip;
}

// Utils --------------------------------------------------------------------------------

void Host::toString(){
	cout << "Host "
		 << " -> IP: " << ipToString(this->ip)
		 << " MAC: " << macToString(this->mac)
		 << " with name " << this->name << "\n";
}

char* Host::macToString(libnet_ether_addr* mac){
	char tmp[18];
	sprintf(tmp, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			this->mac->ether_addr_octet[0],
			this->mac->ether_addr_octet[1],
			this->mac->ether_addr_octet[2],
			this->mac->ether_addr_octet[3],
			this->mac->ether_addr_octet[4],
			this->mac->ether_addr_octet[5]
	);
	return tmp;
}

char* Host::ipToString(uint32_t ip){
	char tmp[16];
	sprintf(tmp, "%d.%d.%d.%d",
			int(((uint8_t*)&ip)[0]),
			int(((uint8_t*)&ip)[1]),
			int(((uint8_t*)&ip)[2]),
			int(((uint8_t*)&ip)[3])
	);
	return tmp;
}
