/*
 * EtherCrafter.cpp
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#include "EtherCrafter.h"

libnet_ether_addr* EtherCrafter::broadcastMac;
libnet_ether_addr* EtherCrafter::zeroedMac;

EtherCrafter::EtherCrafter() : context(NULL) {
	broadcastMac = (libnet_ether_addr*) malloc(sizeof(libnet_ether_addr));
	zeroedMac = (libnet_ether_addr*) malloc(sizeof(libnet_ether_addr));
	uint8_t tmpBroad[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t tmpZero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	memcpy(broadcastMac->ether_addr_octet, tmpBroad, sizeof(tmpBroad));
	memcpy(zeroedMac->ether_addr_octet, tmpZero, sizeof(tmpZero));
}

EtherCrafter::EtherCrafter(libnet_t* context) : context(context) {
	broadcastMac = (libnet_ether_addr*) malloc(sizeof(libnet_ether_addr));
	zeroedMac = (libnet_ether_addr*) malloc(sizeof(libnet_ether_addr));
	uint8_t tmpBroad[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t tmpZero[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	memcpy(broadcastMac->ether_addr_octet, tmpBroad, sizeof(tmpBroad));
	memcpy(zeroedMac->ether_addr_octet, tmpZero, sizeof(tmpZero));
	if(!this->context){
		fprintf(stderr, "webspy::EtherCrafter: [ERRO]LibNet error: received a null context. Try run as sudo.");
		exit(EXIT_FAILURE);
	}
}

EtherCrafter::~EtherCrafter() {
	libnet_clear_packet(this->context);
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

// --------- ETHER HEADER METHODS ------------------------------------

EtherHeader::EtherHeader(unsigned char *buf){
	memcpy(&thaddr, buf, 6);
	buf = buf + 6;
	memcpy(&shaddr, buf, 6);
	buf = buf + 6;
	memcpy(&ptype, buf, 2);
}

const char* EtherHeader::getProtocolTypeName(){
	switch(htons(this->ptype)){
	case ETHERTYPE_ARP:
		return "ARP";
		break;
	case ETHERTYPE_IP:
		return "IP";
		break;
	case ETHERTYPE_IPV6:
		return "IPv6";
		break;
	case ETHERTYPE_LOOPBACK:
		return "Loopback";
		break;
	default:
		return "Other";
		break;
	}
}
