/*
 * Crafter.cpp
 *
 *  Created on: 21/05/2015
 *      Author: rodopoulos
 */

#include "Crafter.h"

uint8_t Crafter::broadcastMAC[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t Crafter::zeroMAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/************************************************************************
 * * * * * * * * CONSTRUCTORS * * * * * * * * * * * * * * * * * * * * * *
 ************************************************************************/
Crafter::Crafter() {
	context = libnet_init(LIBNET_LINK_ADV, NULL, errorBuffer);
	if(context == NULL){
		error(__func__);
	}
}

Crafter::Crafter(const char* iface){
	context = libnet_init(LIBNET_LINK_ADV, iface, errorBuffer);
	if(context == NULL){
		error(__func__);
	}
}

Crafter::~Crafter() {
	libnet_clear_packet(context);
	libnet_destroy(context);
}





/************************************************************************
 * * * * * * * * ACTIONS * * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
void Crafter::send(){
	int response = libnet_write(context);
	if(response == LIBNET_ERROR){
		error(__func__);
	}
}

void Crafter::clear(){
	libnet_clear_packet(context);
}

void Crafter::close(){
	libnet_destroy(context);
}

void Crafter::error(const char* method){
	fprintf(stderr, "Webspy::Crafter::%s > [ERROR] Libnet Error: %s", method, libnet_geterror(context));
	exit(EXIT_FAILURE);
}




/************************************************************************
 * * * * * * * * Getters * * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
uint32_t Crafter::getSize(){
	return libnet_getpacket_size(context);
}




/************************************************************************
 * * * * * * * * Protocols * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
void Crafter::arp(uint16_t op, uint8_t sha[], uint32_t spa, uint8_t tha[], uint32_t tpa){
	auto tag = protocols.find(CRAFTER_ARP);
	if(tag == protocols.end()){
		libnet_ptag_t newTag = libnet_autobuild_arp(
			op,
			sha, (uint8_t*)&spa,
			tha, (uint8_t*)&tpa,
			context
		);
		if(newTag == LIBNET_ERROR){
			error(__func__);
		} else {
			protocols[CRAFTER_ARP] = newTag;
		}
	} else{
		libnet_build_arp(
			ARPHRD_ETHER, ETHERTYPE_IP,	6, 4,
			op,
			sha, (uint8_t*)&spa,
			tha, (uint8_t*)&tpa,
			NULL, 0,
			context,
			tag->second
		);
	}
}

void Crafter::ethernet(uint16_t op, uint8_t smac[], uint8_t tmac[]){
	auto tag = protocols.find(CRAFTER_ETHERNET);
	if(tag == protocols.end()){
		libnet_ptag_t newTag = libnet_build_ethernet(tmac, smac, op, NULL, 0, context, 0);
		if(newTag == LIBNET_ERROR){
			error(__func__);
		} else {
			protocols[CRAFTER_ETHERNET] = newTag;
		}
	} else{
		if(libnet_build_ethernet(tmac, smac, op, NULL, 0, context, tag->second) == LIBNET_ERROR){
			error(__func__);
		}
	}
}
