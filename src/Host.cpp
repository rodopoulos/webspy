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

Host::Host() {
	this->id = currentID;
	currentID++;
}

Host::Host(uint32_t ip, libnet_ether_addr* mac, string name) : ip(ip), mac(mac), name(name){
	this->id = currentID;
	currentID++;
}

Host::~Host() {}

// Getters e Setters --------------------------------------------------------------------

void setIP(uint32_t ip){
}

void setMAC(libnet_ether_addr* mac){

}

void setName(string name){
}

libnet_ether_addr* Host::getMAC(){
	return this->mac.getMACAddress();
}

uint32_t Host::getIP(){
	return this->ip.getIP();
}

// Utils --------------------------------------------------------------------------------

void Host::toString(){
	cout << "Host "
		 << " -> IP: " << this->ip.toString()
		 << " MAC: " << this->mac.toString()
		 << " with name " << this->name << "\n";
}

