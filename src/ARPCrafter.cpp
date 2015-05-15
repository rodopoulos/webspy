/*
 * ARPCrafter.cpp
 *
 *  Created on: 13/05/2015
 *      Author: rodopoulos
 */

#include "ARPCrafter.h"

uint8_t ARPCrafter::zeroedMac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
uint8_t ARPCrafter::broadcastMac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

ARPCrafter::ARPCrafter() : context(NULL) { }

ARPCrafter::ARPCrafter(libnet_t* context) : context(context) {
	if(!this->context){
		fprintf(stderr, "webspy::ARPCrafter: [ERRO]LibNet error: received a null context. Try run as sudo.");
		exit(EXIT_FAILURE);
	}
}

ARPCrafter::~ARPCrafter() {
	libnet_clear_packet(this->context);
}

libnet_ptag_t ARPCrafter::newArp(uint16_t operation,
						libnet_ether_addr* senderMAC,
						uint32_t senderIP,
						libnet_ether_addr* targetMAC,
						uint32_t targetIP)
{
	this->op = operation;
	this->senderIP = senderIP;
	this->senderMAC = senderMAC;
	this->targetIP = targetIP;
	this->targetMAC = targetMAC;
	this->header = libnet_autobuild_arp(this->op,
			this->senderMAC->ether_addr_octet,
			(uint8_t*)&this->senderIP,
			this->targetMAC->ether_addr_octet,
			(uint8_t*)&this->targetIP,
			this->context);
	return this->header;
}

void ARPCrafter::setARPOperation(uint16_t op){
	this->op = op;
	refreshContext();
}

void ARPCrafter::setSenderIP(uint32_t ip){
	this->senderIP = ip;
	refreshContext();
}

void ARPCrafter::setSenderMAC(libnet_ether_addr* mac){
	this->senderMAC = mac;
	refreshContext();
}

void ARPCrafter::setTargetIP(uint32_t ip){
	this->targetIP = ip;
	refreshContext();
}

void ARPCrafter::setTargetMAC(libnet_ether_addr* mac){
	this->targetMAC = mac;
	refreshContext();
}

void ARPCrafter::refreshContext(){
	libnet_build_arp(DLT_EN10MB, ETHERTYPE_IP, 6, 4,
				this->op,
				this->senderMAC->ether_addr_octet,
				(uint8_t*)&this->senderIP,
				this->targetMAC->ether_addr_octet,
				(uint8_t*)&this->targetIP,
				NULL, 0,
				this->context,
				this->header);
}
