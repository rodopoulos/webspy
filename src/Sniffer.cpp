/*
 * Sniffer.cpp
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#include "Sniffer.h"

Sniffer::Sniffer(){ }

Sniffer::Sniffer(char* filterExpression){
	if(pcap_lookupnet(WebSpyGlobals::iface, &this->lan, &this->mask, this->pcapErrBuffer) == -1){
		fprintf(stderr,
				"webspy::Sweeper: [WARN] pCap warning: couldn't get interface %s netmask and IP\n",
				this->pcapErrBuffer
		);
		this->mask = 0;
		this->lan = 0;
	}

	pcapContext = pcap_open_live(WebSpyGlobals::iface, BUFSIZ, 1, 1000, this->pcapErrBuffer);
	if(this->pcapContext == NULL){
		fprintf(stderr,
				"webspy::Sniffer: [ERRO]pCap error: couldn't open device %s: %s",
				WebSpyGlobals::iface,
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(this->pcapContext, &this->filter, filterExpression, 0, this->mask)){
		fprintf(stderr,
				"webspy::Sweeper: [ERRO] pCap error: couldn't compile %s filter: %s",
				this->filter,
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(this->pcapContext, &this->filter) == -1){
		fprintf(stderr,
				"webspy::Sweeper: [ERRO] pCap error: couldn't apply %s filter: %s",
				this->filter,
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
}

Sniffer::~Sniffer() {
	pcap_close(this->context);
}

char* Sniffer::nextPacket(){
	const unsigned char* packet;
	packet = pcap_next(this->context, this->packet);
	if(packet == NULL){
		fprintf(stderr, "webspy::Sweeper: [ERRO] pCap error: error on getting packet");
		exit(EXIT_FAILURE);
	} else{
		return packet;
	}
}
