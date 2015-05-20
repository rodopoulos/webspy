/*
 * Sniffer.cpp
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#include "Sniffer.h"

Sniffer::Sniffer() : filterExpression(NULL) {
	if(pcap_lookupnet(WebSpyGlobals::iface, &this->lan, &this->mask, this->pcapErrBuffer) == -1){
		fprintf(stderr,
				"Webspy::Sweeper: [WARN] pCap warning: couldn't get interface %s netmask and IP\n",
				this->pcapErrBuffer
		);
		this->mask = 0;
		this->lan = 0;
	}

	this->pcapContext = pcap_open_live(WebSpyGlobals::iface, BUFSIZ, 1, 1000, this->pcapErrBuffer);
	if(this->pcapContext == NULL){
		fprintf(stderr,
				"Webspy::Sniffer: [ERRO]pCap error: couldn't open device %s: %s",
				WebSpyGlobals::iface,
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(this->pcapContext, &this->filter, "", 0, this->mask)){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't compile filter: %s",
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(this->pcapContext, &this->filter) == -1){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't apply filter: %s",
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
	this->linkType = pcap_datalink(this->pcapContext);

	printf("Sniffing is on with no filter...\n");
}

Sniffer::Sniffer(char filterExpression[]) : filterExpression(filterExpression){
	if(pcap_lookupnet(WebSpyGlobals::iface, &this->lan, &this->mask, this->pcapErrBuffer) == -1){
		fprintf(stderr,
				"webspy::Sweeper: [WARN] pCap warning: couldn't get interface %s netmask and IP\n",
				this->pcapErrBuffer
		);
		this->mask = 0;
		this->lan = 0;
	}

	this->pcapContext = pcap_open_live(WebSpyGlobals::iface, BUFSIZ, 1, 1000, this->pcapErrBuffer);
	if(this->pcapContext == NULL){
		fprintf(stderr,
				"Webspy::Sniffer: [ERRO]pCap error: couldn't open device %s: %s",
				WebSpyGlobals::iface,
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(this->pcapContext, &this->filter, this->filterExpression, 0, this->mask)){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't compile filter: %s",
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(this->pcapContext, &this->filter) == -1){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't apply filter: %s",
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
	this->linkType = pcap_datalink(this->pcapContext);

	printf("Sniffing with filter \"%s\" is on...\n", this->filterExpression);
}

Sniffer::~Sniffer() {
	pcap_close(this->pcapContext);
}

const unsigned char* Sniffer::nextPacket(){
	const unsigned char* packet;
	packet = pcap_next(this->pcapContext, &this->packet);
	if(packet == NULL){
		fprintf(stderr, "Webspy::Sweeper: [ERRO] pCap error: error on getting packet");
		exit(EXIT_FAILURE);
	} else {
		return packet;
	}
}

void Sniffer::showLANProps(){
	printf("LAN Config:\n");
	printf("    IP Space: %s\n", Host::ipToString((uint32_t)this->lan).c_str());
	printf("    Mask: %s\n", Host::ipToString((this->mask)).c_str());
	printf("    Link type: %s\n", this->getLinkName());
}

const char* Sniffer::getLinkName(){
	switch(this->linkType){
		case DLT_EN10MB:
			return "Ethernet";
			break;
		case DLT_IEEE802:
			return "Wireless";
			break;
		default:
			return "Unknown";
			break;
	}
}
