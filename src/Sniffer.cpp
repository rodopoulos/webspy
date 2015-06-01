/*
 * Sniffer.cpp
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#include "Sniffer.h"

Sniffer::Sniffer() : filterExpression(NULL) {
	if(pcap_lookupnet(Globals::iface, &lan, &mask, pcapErrBuffer) == PCAP_ERROR){
		fprintf(stderr,
				"Webspy::Sweeper: [WARN] pCap warning: couldn't get interface %s netmask and IP\n",
				this->pcapErrBuffer
		);
		mask = 0;
		lan = 0;
	}

	pcapContext = pcap_open_live(Globals::iface, BUFSIZ, 1, 1000, pcapErrBuffer);
	if(pcapContext == NULL){
		fprintf(stderr,
				"Webspy::Sniffer: [ERRO]pCap error: couldn't open device %s: %s\n",
				Globals::iface,
				pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setdirection(pcapContext, PCAP_D_IN) == PCAP_ERROR){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > [WARN] Pcap error: %s"
			"can't set packet reception direction\n",
			this->pcapErrBuffer
		);
	}

	if(pcap_compile(pcapContext, &filter, "", 0, mask)){
		fprintf(stderr,
				"Webspy::Sweeper::Constructor > [ERRO] Pcap error: can't compile filter: %s\n",
				pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(pcapContext, &filter) == PCAP_ERROR){
		fprintf(stderr,
				"Webspy::Sweeper::Constructor [ERRO] Pcap error: can't apply filter: %s\n",
				pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
	linkType = pcap_datalink(pcapContext);

	if(Globals::verbose)
		printf("Sniffing is on with no filter...\n");
}

Sniffer::Sniffer(char filterExpression[]) : filterExpression(filterExpression){
	if(pcap_lookupnet(Globals::iface, &lan, &mask, pcapErrBuffer) == PCAP_ERROR){
		fprintf(stderr,
			"Webspy::Sweeper: [WARN] pCap warning: couldn't get interface %s netmask and IP\n",
			Globals::iface
		);
		mask = 0;
		lan = 0;
	}

	pcapContext = pcap_open_live(Globals::iface, BUFSIZ, 1, 1000, pcapErrBuffer);
	if(pcapContext == NULL){
		fprintf(stderr,
				"Webspy::Sniffer: [ERRO]pCap error: couldn't open device %s: %s\n",
				Globals::iface,
				pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}

	/*
	if(pcap_setdirection(this->pcapContext, PCAP_D_IN) == PCAP_ERROR){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > [ERRO] Pcap error: %s"
			"can't set packet reception direction\n",
			this->pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
	*/

	if(pcap_compile(pcapContext, &filter, this->filterExpression, 0, mask) == PCAP_ERROR){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't compile filter: %s\n",
				filterExpression
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(pcapContext, &filter) == PCAP_ERROR){
		fprintf(stderr,
				"Webspy::Sweeper: [ERRO] pCap error: couldn't apply filter: %s\n",
				pcapErrBuffer
		);
		exit(EXIT_FAILURE);
	}
	linkType = pcap_datalink(pcapContext);

	if(Globals::verbose)
		printf("Sniffing with filter \"%s\" is on...\n", this->filterExpression);
}

Sniffer::~Sniffer() {
	pcap_freecode(&this->filter);
	pcap_close(pcapContext);
}

void Sniffer::close(){
	pcap_close(pcapContext);
}

const unsigned char* Sniffer::nextPacket(){
	const unsigned char* packet;
	packet = pcap_next(pcapContext, &this->packet);
	if(packet == NULL){
		// fprintf(stderr, "Webspy::Sweeper::pcap [ERRO] error on getting packet\n");
		// exit(EXIT_FAILURE);
		return (const unsigned char*) NULL;
	} else {
		return packet;
	}
}

void Sniffer::listen(pcap_handler callback){
	int listener = pcap_loop(pcapContext, -1, callback, (u_char*)pcapContext);
	if(listener == PCAP_ERROR){
		fprintf(stderr, "Webspy::Sniffer: [ERRO] pCap error: pcap_loop() error\n");
		exit(EXIT_FAILURE);
	}
}

void Sniffer::listen(pcap_handler callback, int packets){
	int listener = pcap_loop(pcapContext, packets, callback, (u_char*)pcapContext);
	if(listener == PCAP_ERROR){
		fprintf(stderr, "Webspy::Sniffer: [ERRO] pCap error: pcap_loop() error\n");
		exit(EXIT_FAILURE);
	}
}

void Sniffer::listenWithTimeout(pcap_handler callback){
	int listener = pcap_dispatch(pcapContext, -1, callback, (u_char*)pcapContext);
	if(listener == PCAP_ERROR){
		fprintf(stderr, "Webspy::Sniffer: [ERRO] pCap error: pcap_loop() error\n");
		exit(EXIT_FAILURE);
	}
}

void Sniffer::setTimeout(int time){
	pcap_set_timeout(pcapContext, time);
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
