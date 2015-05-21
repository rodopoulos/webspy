/*
 * Sniffer.cpp
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#include "Sniffer.h"

Sniffer::Sniffer() : filterExpression(NULL) {
	if(pcap_lookupnet(WebSpyGlobals::iface, &this->lan, &this->mask, this->pcapErrBuffer) == PCAP_ERROR){
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

	if(pcap_setfilter(this->pcapContext, &this->filter) == PCAP_ERROR){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't apply filter: %s",
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
	this->linkType = pcap_datalink(this->pcapContext);

	if(WebSpyGlobals::verbose)
		printf("Sniffing is on with no filter...\n");
}

Sniffer::Sniffer(char filterExpression[]) : filterExpression(filterExpression){
	if(pcap_lookupnet(WebSpyGlobals::iface, &this->lan, &this->mask, this->pcapErrBuffer) == PCAP_ERROR){
		fprintf(stderr,
				"webspy::Sweeper: [WARN] pCap warning: couldn't get interface %s netmask and IP\n",
				WebSpyGlobals::iface
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

	if(pcap_compile(this->pcapContext, &this->filter, this->filterExpression, 0, this->mask) == PCAP_ERROR){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't compile filter: %s",
				this->filterExpression
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(this->pcapContext, &this->filter) == PCAP_ERROR){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't apply filter: %s",
				this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
	this->linkType = pcap_datalink(this->pcapContext);
	//setLinkHrdLen(this->linkType);

	if(WebSpyGlobals::verbose)
		printf("Sniffing with filter \"%s\" is on...\n", this->filterExpression);
}

Sniffer::~Sniffer() {
	pcap_freecode(&this->filter);
	pcap_close(this->pcapContext);
}

const unsigned char* Sniffer::nextPacket(){
	const unsigned char* packet;
	packet = pcap_next(this->pcapContext, &this->packet);
	if(packet == NULL){
		// fprintf(stderr, "Webspy::Sweeper::pcap [ERRO] error on getting packet\n");
		// exit(EXIT_FAILURE);
		return (const unsigned char*) NULL;
	} else {
		return packet;
	}
}

void Sniffer::listen(pcap_handler filterFunction){
	int listener = pcap_loop(this->pcapContext, -1, filterFunction, NULL);
	if(listener == PCAP_ERROR){
		fprintf(stderr, "Webspy::Sniffer: [ERRO] pCap error: pcap_loop() error");
		exit(EXIT_FAILURE);
	} else if(listener != PCAP_ERROR_BREAK){
		fprintf(stderr, "Webspy::Sniffer: [ERRO] pCap error: listen failed");
		exit(EXIT_FAILURE);
	}
}

void Sniffer::showLANProps(){
	printf("LAN Config:\n");
	printf("    IP Space: %s\n", Host::ipToString((uint32_t)this->lan).c_str());
	printf("    Mask: %s\n", Host::ipToString((this->mask)).c_str());
	printf("    Link type: %s\n", this->getLinkName());
}

void setLinkHrdLen(int linkType){
	switch (linkType){
	    case DLT_NULL:
	        //this->linkHdrLen = 4;
	        break;

	    case DLT_EN10MB:
	    	//this->linkHdrLen = 14;
	        break;

	    case DLT_SLIP:
	    case DLT_PPP:
	    	//this->linkHdrLen = 24;
	        break;
	 }
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
