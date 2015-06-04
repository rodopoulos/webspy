/*
 * Sniffer.cpp
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#include "Sniffer.h"

/************************************************************************
 * * * * * * * * Constructors and Destructor * * * * * * * * * * * * * **
 ************************************************************************/
Sniffer::Sniffer() {
	getLANProps();
	handle = pcap_create(Globals::iface, errBuf);
	if(handle == NULL){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > "
			"[ERRO] Pcap error: can't open device %s for capture: %s\n",
			Globals::iface,
			errBuf
		);
	}

	if(pcap_set_promisc(handle, 1)){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > "
			"[ERRO] pCap error: can't set promiscous mode on interface: %s\n",
			errBuf
		);
		exit(EXIT_FAILURE);
	}

	pcap_setdirection(handle, PCAP_D_IN);
	// TODO Ver como fazer para lidar com esta diretiva da Pcap
	/* if(pcap_setdirection(handle, PCAP_D_IN)){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > "
			"[ERRO] pCap error: can't set packet capture direction\n"
		);
		exit(EXIT_FAILURE);
	} */
}


Sniffer::Sniffer(char filterExpression[]) : filterExpression(filterExpression){
	getLANProps();

	handle = pcap_open_live(Globals::iface, BUFSIZ, 1, 1000, errBuf);
	if(handle == NULL){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > "
			"[ERRO] Pcap error: can't open device %s: %s\n",
			Globals::iface,
			errBuf
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(handle, &filter, this->filterExpression, 0, mask) == PCAP_ERROR){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > "
			"[ERRO] Pcap error: can't compile filter: %s\n",
			filterExpression
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(handle, &filter) == PCAP_ERROR){
		fprintf(stderr,
			"Webspy::Sniffer::Constructor > "
			"[ERRO] pCap error: cant't apply filter: %s\n",
			errBuf
		);
		exit(EXIT_FAILURE);
	}

	if(Globals::verbose)
		printf("Sniffing with filter \"%s\" is on...\n", this->filterExpression);
}


Sniffer::~Sniffer() {
	pcap_freecode(&this->filter);
	pcap_close(handle);
}





/************************************************************************
 * * * * * * * * Modifiers * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
void Sniffer::init(){
	int response = pcap_activate(handle);
	if(response == PCAP_ERROR_ACTIVATED){
		fprintf(stderr,
			"Webspy::Sniffer::init > "
			"[WARN] sniffer already activated"
		);
	} else if(response){
		fprintf(stderr,
			"Webspy::Sniffer::init > "
			"[WARN] error on initing the sniffer: %s",
			errBuf
		);
		exit(EXIT_FAILURE);
	}
}


void Sniffer::breakLoop(){
	pcap_breakloop(handle);
}

void Sniffer::close(){
	pcap_freecode(&filter);
	pcap_close(handle);
}




/************************************************************************
 * * * * * * * * Setters * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
void Sniffer::setFilter(const char* filterExp){
	if(pcap_compile(handle, &filter, filterExp, 0, mask)){
		fprintf(stderr,
			"Webspy::Sniffer::setFilter > "
			"[ERRO] can't compile filter\n"
			"    > Filter expression: %s\n"
			"    > Pcap error: %s\n",
			filterExp, pcap_geterr(handle)
		);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(handle, &filter)){
		fprintf(stderr,
			"Webspy::Sniffer::setFilter > "
			"[ERRO] Pcap error: can't apply filter: %s\n",
			pcap_geterr(handle)
		);
		exit(EXIT_FAILURE);
	}
}


void Sniffer::setTimeout(int time){
	pcap_set_timeout(handle, time);
}


void Sniffer::setDirection(pcap_direction_t direction){
	pcap_setdirection(handle, direction);
}





/************************************************************************
 * * * * * * * * Listeners * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
const unsigned char* Sniffer::nextPacket(){
	const unsigned char* packet;
	packet = pcap_next(handle, &this->packet);
	if(packet == NULL){
		// fprintf(stderr, "Webspy::Sniffer::pcap [ERRO] error on getting packet\n");
		// exit(EXIT_FAILURE);
		return (const unsigned char*) NULL;
	} else {
		return packet;
	}
}

void Sniffer::listen(pcap_handler callback){
	int listener = pcap_loop(handle, -1, callback, (u_char*)handle);
	if(listener == PCAP_ERROR){
		fprintf(stderr,
			"Webspy::Sniffer::listen > "
			"[ERRO] pCap error: pcap_loop() error: %s\n",
			errBuf
		);
		exit(EXIT_FAILURE);
	}
}


void Sniffer::listen(pcap_handler callback, u_char* args){
	int listener = pcap_loop(handle, -1, callback, args);
	if(listener == PCAP_ERROR){
		fprintf(stderr,
			"Webspy::Sniffer::listen > "
			"[ERRO] pCap error: pcap_loop() error: %s\n",
			errBuf
		);
		exit(EXIT_FAILURE);
	}
}





/************************************************************************
 * * * * * * * * Getters * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
void Sniffer::getLANProps(){
	if(pcap_lookupnet(Globals::iface, &lan, &mask, errBuf)){
		fprintf(stderr,
			"Webspy::Sniffer::retrieveLANProps > "
			"[WARN] pCap warning: can't retrieve LAN properties: %s\n",
			errBuf
		);
		mask = 0;
		lan = 0;
	}
}

void Sniffer::showLANProps(){
	printf("LAN Config:\n");
	printf("    IP Space: %s\n", Host::ipToString((uint32_t)lan).c_str());
	printf("    Mask: %s\n", Host::ipToString((mask)).c_str());
	printf("    Link type: %s\n", getLinkName());
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
