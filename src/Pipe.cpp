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

	if(pthread_create(&thread, nullptr, connect, args) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
}

void* Pipe::connect(void* arguments){
	//char filter[] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
	char filter[] = "tcp port 80";
	Sniffer sniffer(filter);
	printf("Pipe thread is running\n");
	sniffer.listen(relay, (u_char*)arguments);
	printf("Sai do listen\n");
	return nullptr;
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	pipeListenerArgs* arguments = (pipeListenerArgs*) args;

	Ethernet ether((unsigned char*) packet);
	printf("Chegou pacote. Tam.: %u bytes ", header->len);
	if(!memcmp(Globals::attacker.mac, ether.thaddr, 6)){
		IP ip((unsigned char*) packet);
		if(arguments->src->ip == ip.src){
			printf("Vitima ->");
		} else{
			printf("%s -> ", Host::ipToString(ip.src).c_str());
		}
		printf("Atacante");
	} else{
		printf("%s", Host::macToString(ether.thaddr).c_str());
	}

	printf("\n");
	/*if(htons(ether.ptype) == ETHERTYPE_IP){
		if(!memcmp(ether.shaddr, pipe->src.mac->ether_addr_octet, 6)){
			printf("Recebi um pacote de %s\n", pipe->src.name.c_str());
		}
	}*/
}
