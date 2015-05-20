/*
 * ARPCrafter.cpp
 *
 *  Created on: 13/05/2015
 *      Author: rodopoulos
 */

#include "ARPCrafter.h"

uint8_t ARPCrafter::zeroedMac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
uint8_t ARPCrafter::broadcastMac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

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

libnet_ptag_t ARPCrafter::newARP(uint16_t operation,
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

	if(this->header == -1){
		fprintf(stderr, "webspy::ARPCrafter: [ERRO]LibNet error: couldn't create ARP packet.");
		exit(EXIT_FAILURE);
	}

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

void ARPCrafter::setBroadcastMAC(){
	memcpy(this->targetMAC->ether_addr_octet, broadcastMac, sizeof(broadcastMac) + 1);
	refreshContext();
}

void ARPCrafter::refreshContext(){
	libnet_build_arp(ARPHRD_ETHER, ETHERTYPE_IP, 6, 4,
				this->op,
				this->senderMAC->ether_addr_octet,
				(uint8_t*)&this->senderIP,
				this->targetMAC->ether_addr_octet,
				(uint8_t*)&this->targetIP,
				NULL, 0,
				this->context,
				this->header);
}

const char* ARPCrafter::getARPOperationName(int op){
	switch(op){
		case ARPOP_REPLY:
			return "ARP_REPLY";
			break;
		case ARPOP_REQUEST:
			return "ARP_REQUEST";
			break;
		default:
			return "Other";
			break;
	}
}

ARPPacket::ARPPacket(unsigned char* buf){
	buf += 14; // Jumping Ethernet Header
	memcpy(&htype, buf, 14);
	buf += 14; // Jumping ARP Header
	memcpy(&spaddr, buf, 10);
	buf += 10; // Jumping Sender MAC and IP
	memcpy(&tpaddr, buf, 4);
}
