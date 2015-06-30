/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: Felipe Rodopoulos
 */

#include "Pipe.h"

Pipe::Pipe(Host& src, Host& dst) : src(src), dst(dst){}
Pipe::~Pipe() { }

void Pipe::init(){
	pthread_t thread;
	pipeListenerArgs *args = new pipeListenerArgs;
	args->src = &src;
	args->dst = &dst;
	args->sniffer = nullptr;
	args->crafter = nullptr;

	if(pthread_create(&thread, nullptr, connect, args) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
}

void* Pipe::connect(void* args){
	printf("Pipe thread is running\n");
	pipeListenerArgs* arguments = (pipeListenerArgs*) args;

	Crafter crafter(Globals::iface);
	crafter.ethernet(
		ETHERTYPE_IP,
		arguments->src->mac->ether_addr_octet,
		arguments->dst->mac->ether_addr_octet
	);

	char filter[] = "tcp port 80";
	Sniffer sniffer(filter);


	arguments->crafter = &crafter;
	sniffer.listen(relay, (u_char*)args);

	printf("Sai do listen\n");
	return nullptr;
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	pipeListenerArgs* arguments = (pipeListenerArgs*) args;
	// printf("Chegou pacote. Tam.: %u bytes | ", header->len);

	Ethernet* ether = (Ethernet*) packet;
	if(!memcmp(Globals::attacker.mac, ether->thaddr, 6)){
		memcpy(ether->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
		memcpy(ether->thaddr, arguments->dst->mac->ether_addr_octet, 6);

		IP* ip = (IP*) (packet + 14);
		if(ip->src == arguments->src->ip){
			arguments->sniffer->send(packet, header->len);
		}
	}
}

/* arguments->crafter->ip(ip);
TCP* tcp = (TCP*) (packet + LIBNET_ETH_H + LIBNET_IPV4_H);
if(tcp->flags && TCP_SYN){
	arguments->crafter->tcp(tcp);
	arguments->crafter->send();
} else if(tcp->flags && TCP_RST){

} */
