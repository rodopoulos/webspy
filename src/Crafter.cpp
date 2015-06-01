/*
 * Crafter.cpp
 *
 *  Created on: 21/05/2015
 *      Author: rodopoulos
 */

#include "Crafter.h"

uint8_t Crafter::broadcastMAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t Crafter::zeroMAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

Crafter::Crafter() {
	this->context = libnet_init(LIBNET_LINK_ADV, NULL, this->errorBuffer);
	if(!this->context){
		error();
	}
}

Crafter::Crafter(const char* iface){
	this->context = libnet_init(LIBNET_LINK_ADV, iface, this->errorBuffer);
	if(!this->context){
		error();
	}
}

Crafter::~Crafter() {
	libnet_clear_packet(this->context);
	libnet_destroy(this->context);
}

void Crafter::send(){
	int response = libnet_write(this->context);
	if(response == LIBNET_ERROR){
		error();
	}
}

void Crafter::clear(){
	libnet_clear_packet(this->context);
}

void Crafter::close(){
	libnet_destroy(this->context);
}

void Crafter::error(){
	fprintf(stderr, "Webspy::Crafter::libnet > [ERROR] %s", libnet_geterror(this->context));
	exit(EXIT_FAILURE);
}

void Crafter::arp(uint16_t op, uint8_t sha[], uint32_t spa, uint8_t tha[], uint32_t tpa){
	auto tag = this->protocols.find(CRAFTER_ARP);
	if(tag == this->protocols.end()){
		libnet_ptag_t newTag = libnet_autobuild_arp(
			op,
			sha, (uint8_t*)&spa,
			tha, (uint8_t*)&tpa,
			this->context
		);
		if(newTag == LIBNET_ERROR){
			error();
		} else {
			this->protocols[CRAFTER_ARP] = newTag;
		}
	} else{
		libnet_build_arp(
			ARPHRD_ETHER, ETHERTYPE_IP,	6, 4,
			op,
			sha, (uint8_t*)&spa,
			tha, (uint8_t*)&tpa,
			NULL, 0,
			this->context,
			tag->second
		);
	}
}

void Crafter::ethernet(uint16_t op, uint8_t smac[], uint8_t tmac[]){
	auto tag = this->protocols.find(CRAFTER_ETHERNET);
	if(tag == this->protocols.end()){
		libnet_ptag_t newTag = libnet_build_ethernet(tmac, smac, op, NULL, 0, this->context, 0);
		if(newTag == LIBNET_ERROR){
			error();
		} else {
			this->protocols[CRAFTER_ETHERNET] = newTag;
		}
	} else{
		if(libnet_build_ethernet(tmac, smac, op, NULL, 0, this->context, tag->second) == LIBNET_ERROR)
			error();
	}
}
