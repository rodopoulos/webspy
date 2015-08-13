/*
 * Host.cpp
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#include "Host.h"

using namespace Tins;

Host::Host(){}

Host::Host(IPv4Address ip, HWAddress<6> mac) : ip(ip), mac(mac) {}

Host::~Host() {
	// TODO Auto-generated destructor stub
}

void Host::setName(std::string name){
	this->name = name;
}

void Host::setIP(IPv4Address ip){
	//std::cout << ip << std::endl;
	this->ip = ip;
}

void Host::setMAC(HWAddress<6> mac){
	this->mac = mac;
}

bool Host::isDefined(){
	return mac.size() != 0;
}

void Host::toString(){
	std::cout << "\033[1;34m[HOST]\033[0m"
			  << std::setw(11) << ip.to_string()  << " | "
			  << std::setw(17) << mac.to_string() << " | "
			  << name << std::endl;
}
