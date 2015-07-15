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
Crafter::Crafter() : context(NULL){}

Crafter::Crafter(const char* iface){
	context = libnet_init(LIBNET_LINK_ADV, iface, errorBuffer);
	if(context == NULL){
		error(__func__);
	}
}

Crafter::~Crafter() {
	libnet_destroy(context);
}





/************************************************************************
 * * * * * * * * ACTIONS * * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
void Crafter::init(const char* iface){
	context = libnet_init(LIBNET_LINK_ADV, iface, errorBuffer);
	if(context == NULL){
		error(__func__);
	}
}

void Crafter::send(){
	int response = libnet_write(context);
	if(response == LIBNET_ERROR){
		error(__func__);
	}
}

void Crafter::sendRaw(const unsigned char* data, uint32_t size){
	int response = libnet_adv_write_link(context, data, size);
	if(response == LIBNET_ERROR)
		error(__func__);
}

void Crafter::sendRaw(Packet packet){
	int response = libnet_adv_write_link(context, packet.data, packet.len);
	if(response == LIBNET_ERROR)
		error(__func__);
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
uint32_t Crafter::getPacketSize(){
	return libnet_getpacket_size(context);
}

uint32_t Crafter::getInterfaceIP(){
	return libnet_get_ipaddr4(context);
}

libnet_ether_addr* Crafter::getInterfaceMAC(){
	return libnet_get_hwaddr(context);
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

void Crafter::ethernet(Ethernet* ether){
	auto tag = protocols.find(CRAFTER_ETHERNET);
	if(tag == protocols.end()){
		libnet_ptag_t newTag = libnet_build_ethernet(
			ether->thaddr,
			ether->shaddr,
			ether->ptype,
			NULL,
			0,
			context,
			0
		);
		if(newTag == LIBNET_ERROR){
			error(__func__);
		} else {
			protocols[CRAFTER_ETHERNET] = newTag;
		}
	} else{
		int response = libnet_build_ethernet(
			ether->thaddr,
			ether->shaddr,
			ether->ptype,
			NULL,
			0,
			context,
			tag->second
		);
		if(response == LIBNET_ERROR){
			error(__func__);
		}
	}
}

void Crafter::ip(uint16_t len, uint32_t src, uint32_t dst){
	auto tag = protocols.find(CRAFTER_IP);
	if(tag == protocols.end()){
		libnet_ptag_t newTag = libnet_build_ipv4(len, 0, 0, 0, 255, IPPROTO_TCP, 0, src, dst, nullptr, 0, context, 0);
		if(newTag == LIBNET_ERROR){
			error(__func__);
		} else {
			protocols[CRAFTER_IP] = newTag;
		}
	} else {
		if(libnet_build_ipv4(len, 0, 0, 0, 255, IPPROTO_TCP, 0, src, dst, nullptr, 0, context, tag->second) == LIBNET_ERROR){
			error(__func__);
		}
	}
}

void Crafter::ip(IP* ip){
	auto tag = protocols.find(CRAFTER_IP);
	if(tag == protocols.end()){
		libnet_ptag_t newTag = libnet_build_ipv4(
			ip->len,
			0, 0, 0, // tos, id, frag
			ip->ttl,
			ip->protocol,
			0, // checksum
			ip->src,
			ip->dst,
			nullptr, 0,
			context, 0
		);
		if(newTag == LIBNET_ERROR){
			error(__func__);
		} else {
			protocols[CRAFTER_IP] = newTag;
		}
	} else {
		int response = libnet_build_ipv4(
			ip->len,
			0, 0, 0, // tos, id, frag
			ip->ttl,
			ip->protocol,
			0, // checksum
			ip->src,
			ip->dst,
			nullptr, 0,
			context, tag->second
		);
		if(response == LIBNET_ERROR){
			error(__func__);
		}
	}
}

void Crafter::tcp(TCP* tcp){
	auto tag = protocols.find(CRAFTER_TCP);
	uint16_t control = ((uint16_t) tcp->offrsv) << 8 || tcp->flags;
	if(tag == protocols.end()){
		libnet_ptag_t newTag = libnet_build_tcp(
			tcp->sport,
			tcp->dport,
			tcp->seqid,
			tcp->ackid,
			control,
			tcp->window,
			tcp->checksum,
			tcp->urgptr,
			0,
			NULL, 0,
			context, 0
		);
		if(newTag == LIBNET_ERROR){
			error(__func__);
		} else {
			protocols[CRAFTER_TCP] = newTag;
		}
	} else {
		int response = libnet_build_tcp(
			tcp->sport,
			tcp->dport,
			tcp->seqid,
			tcp->ackid,
			control,
			tcp->window,
			tcp->checksum,
			tcp->urgptr,
			0,
			NULL, 0,
			context, tag->second
		);
		if(response == LIBNET_ERROR){
			error(__func__);
		}
	}
}
