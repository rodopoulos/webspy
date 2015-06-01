/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: rodopoulos
 */

#include "Pipe.h"

Pipe::Pipe(Host src, Host dst) : src(src), dst(dst) {
	sniffer("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)");

	if(pthread_create(thread, NULL, listeningPackets, NULL) < 0){
		printf("Webspy::Pipe::Constructor > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
}

Pipe::~Pipe() {
	// TODO Auto-generated destructor stub
}

void Pipe::listeningPackets(){
	sniffer.listen(relay);
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	Ethernet ether((unsigned char*) packet);

	if(htons(ether.ptype) == ETHERTYPE_IP){
		if(!memcmp(ether.ptype, src.mac->ether_addr_octet, 6)){
			printf("Recebi um pacote de %s\n", src.name.c_str());
		}
	}
}
