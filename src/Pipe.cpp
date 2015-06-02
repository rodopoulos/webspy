/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: rodopoulos
 */

#include "Pipe.h"

Pipe::Pipe(Host& src, Host& dst) : src(src), dst(dst) {
	char filter[] = "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)";
	sniffer.init();
	sniffer.setFilter(filter);

	if(pthread_create(&thread, NULL, listeningPackets, &sniffer)){
		printf("Webspy::Pipe::Constructor > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
}

Pipe::~Pipe() {
	// TODO Auto-generated destructor stub
}

void* Pipe::listeningPackets(void* args){
	Sniffer* sniffer = (Sniffer*) args;
	printf("\nDeu ate aqui\n");
	sniffer->listen(relay);
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	// Pipe* pipe = (Pipe*) args;
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
