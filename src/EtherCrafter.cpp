/*
 * EtherCrafter.cpp
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#include "EtherCrafter.h"

EtherCrafter::EtherCrafter() : context(NULL) {}

EtherCrafter::EtherCrafter(libnet_t* context) : context(context) {
	if(!this->context){
		fprintf(stderr, "webspy::EtherCrafter: [ERRO]LibNet error: received a null context. Try run as sudo.");
		exit(EXIT_FAILURE);
	}
}

EtherCrafter::~EtherCrafter() {
	// TODO Auto-generated destructor stub
}

libnet_ptag_t EtherCrafter::newEther(libnet_ether_addr* senderMAC, libnet_ether_addr* targetMAC, uint16_t protocol){
	this->senderMAC = senderMAC;
	this->targetMAC = targetMAC;
	this->upperProtocol = protocol;
	this->header = libnet_autobuild_ethernet(this->targetMAC->ether_addr_octet, this->upperProtocol, this->context);

	if(this->header == -1){
		fprintf(stderr, "webspy::EtherCrafter: [ERRO]LibNet error: couldn't create Ethernet packet.");
		exit(EXIT_FAILURE);
	}

	return this->header;
}

void EtherCrafter::setSenderMAC(libnet_ether_addr* mac){
	this->senderMAC = senderMAC;
	refreshContext();
}

void EtherCrafter::setTargetMAC(libnet_ether_addr* mac){
	this->targetMAC = targetMAC;
	refreshContext();
}

void EtherCrafter::setUpperProtocol(uint16_t protocol){
	this->upperProtocol = protocol;
	refreshContext();
}

void EtherCrafter::setBroadcasMAC(){
	memcpy(this->targetMAC->ether_addr_octet, broadcastMac, sizeof(broadcastMac) + 1);
	refreshContext();
}

void EtherCrafter::refreshContext(){
	libnet_build_ethernet(
		this->targetMAC->ether_addr_octet,
		this->senderMAC->ether_addr_octet,
		this->upperProtocol,
		NULL, 0,
		this->context,
		this->header
	);
}
