/*
 * Host.cpp
 *
 *  Created on: 15/04/2015
 *      Author: root
 */

// this
#include "Host.h"

using namespace std;

// Constructors ------------------------------------------------------------------------

Host::Host() : ip(0), mac(NULL), name("") {}

Host::Host(uint32_t ip, libnet_ether_addr* mac, string name) : ip(ip), mac(mac), name(name) {}

Host::Host(uint32_t ip, uint8_t mac[], string name){
	// TODO checar se isto está certo
	this->ip = ip;
	this->mac = (libnet_ether_addr*) malloc(sizeof(libnet_ether_addr));
	memcpy(this->mac->ether_addr_octet, mac, 6);
	this->name = name;
}

Host::~Host() {}

// Getters e Setters --------------------------------------------------------------------

void Host::setIP(uint32_t ip){
	this->ip = ip;
}

void Host::setMAC(libnet_ether_addr* mac){
	this->mac = mac;
}

void Host::setMAC(uint8_t mac[]){
	// TODO checar se isto está certo
	this->mac = (libnet_ether_addr*) malloc(sizeof(libnet_ether_addr));
	memcpy(this->mac->ether_addr_octet, mac, 6);
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
	printf(
		"[HOST] IP: %s | MAC: %s",
		ipToString(this->ip).c_str(),
		mac ? macToString(this->mac).c_str() : "<NULL>"
	);
	if(this->name != "")
		printf(" | Name/Vendor: %s\n", this->name.c_str());
	else
		printf("\n");
}

std::string Host::macToString(libnet_ether_addr* mac){
	char tmp[18];
	sprintf(tmp, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
		mac->ether_addr_octet[0],
		mac->ether_addr_octet[1],
		mac->ether_addr_octet[2],
		mac->ether_addr_octet[3],
		mac->ether_addr_octet[4],
		mac->ether_addr_octet[5]
	);
	return string(tmp);
}

std::string Host::macToString(uint8_t mac[]){
	char tmp[18];
	sprintf(tmp, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
	);
	return string(tmp);
}

std::string Host::ipToString(uint32_t ip){
	char tmp[16];
	sprintf(tmp, "%d.%d.%d.%d",
		int(((uint8_t*)&ip)[0]),
		int(((uint8_t*)&ip)[1]),
		int(((uint8_t*)&ip)[2]),
		int(((uint8_t*)&ip)[3])
	);
	return string(tmp);
}

bool Host::isSameMAC(uint8_t mac1[], uint8_t mac2[]){
	int i;
	for (i = 0; i < 6; i++){
		if(mac1[i] != mac2[i])
			return false;
	}
	return true;
}

char* Host::getMACVendor(uint8_t mac[]){
	/*char tmac[6];
	int i = 0;

	sprintf(tmac, "%02x%02x%02x", mac[0], mac[1], mac[2]);

	Convert mac prefix to upper
	for (i=0; i<6; i++)
		tmac[i] = toupper(tmac[i]);

	for (i=0; i<8436; i++){
		if (strcmp(oui_table[i].prefix, tmac) == 0)
			return oui_table[i].vendor;
	} */

	char* str = "Unknown vendor";
	return str;
}
