/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: rodopoulos
 */

#include "Pipe.h"

Pipe::Pipe(Host& src, Host& dst) : src(src), dst(dst) {
	char filter[] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
	Sniffer sniffer(filter);
	this->sniffer = sniffer;

	if(pthread_create(&thread, NULL, listeningPackets, this) < 0){
		printf("Webspy::Pipe::Constructor > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
}

Pipe::~Pipe() {
	// TODO Auto-generated destructor stub
}

void* Pipe::listeningPackets(void* pipe){
	Pipe* ptr = (Pipe*) pipe;
	ptr->sniffer.listen(relay);
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	Pipe* pipe = (Pipe*) args;
	Ethernet ether((unsigned char*) packet);

	if(htons(ether.ptype) == ETHERTYPE_IP){
		if(!memcmp(ether.shaddr, pipe->src.mac->ether_addr_octet, 6)){
			printf("Recebi um pacote de %s\n", pipe->src.name.c_str());
		}
	}
}
