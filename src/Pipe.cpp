/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: Felipe Rodopoulos
 */

#include "Pipe.h"

Pipe::Pipe(Host& src, Host& dst) : src(src), dst(dst) {}

Pipe::~Pipe() { }

void Pipe::init(){
	pthread_t thread;
	pipeListenerArgs *args = new pipeListenerArgs;
	args->src = &src;
	args->dst = &dst;
	args->sniffer = nullptr;

	if(pthread_create(&thread, NULL, connect, args) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
}

void* Pipe::connect(void* arguments){
	char filter[] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
	Sniffer sniffer(filter);
	printf("Sniffer on Pipe is settled\n");
	sniffer.listen(relay, (u_char*)arguments);
	return nullptr;
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	pipeListenerArgs* arguments = (pipeListenerArgs*) args;

	printf("Argumentos\n  Src: %s\n  Dst: %s\n");
	Ethernet ether((unsigned char*) packet);
	printf(
		"Pacote Ether tipo %s de %s para %s\n",
		htons(ether.ptype) == ETHERTYPE_IP ? "IP" : "Other",
		Host::macToString(ether.shaddr).c_str(),
		Host::macToString(ether.thaddr).c_str()
	);

	/*if(htons(ether.ptype) == ETHERTYPE_IP){
		if(!memcmp(ether.shaddr, pipe->src.mac->ether_addr_octet, 6)){
			printf("Recebi um pacote de %s\n", pipe->src.name.c_str());
		}
	}*/
}
