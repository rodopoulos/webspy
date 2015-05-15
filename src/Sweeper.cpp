/*
 * Sweeper.cpp
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#include <iostream>

// this
#include "Sweeper.h"

// local
#include "WebSpyGlobals.h"

using namespace std;

// Static Variables --------------------------------------------------------------
pcap_t* 			Sweeper::pcapContext;
char				Sweeper::pcapErrBuffer[PCAP_ERRBUF_SIZE];
bpf_u_int32			Sweeper::netMask;
libnet_ptag_t		Sweeper::arpHeader;
libnet_ptag_t		Sweeper::etherHeader;
bpf_u_int32			Sweeper::ip;
struct bpf_program 	Sweeper::filter;

// Constructors --------------------------------------------------------------
Sweeper::Sweeper(){ }

Sweeper::~Sweeper(){ }

// Public --------------------------------------------------------------
vector<Host> Sweeper::sweep(){
	printf("\n== INITING SWEEP ==\n");
	configARPSniffer();
	printf("\nARP Sniffing is on...\n");
	printf("Starting to send ARP Requests...\n\n");

	uint32_t currentIp = (uint32_t)ip;
	uint32_t range = ~(uint32_t)netMask;
	range = (range >> 24) + (range << 8 >> 16 ) + (range << 16 >> 8) + (range << 24) + 1;
	printf("LAN IP: %s\n", Host::ipToString(currentIp).c_str());
	printf("Net mask: %s\n", Host::ipToString((uint32_t)netMask).c_str());
	printf("Number of probes: %u\n", range);

	ARPCrafter arpCrafter(WebSpyGlobals::context);
	arpCrafter.

	vector<Host> tmp;
	uint32_t i;
	for(i = 0; i < range; i++){
		printf("Probing host on %s ...\n", Host::ipToString(currentIp).c_str());
		currentIp += 1 << 24; // Iterando um IP em little endian
	}

	return tmp;
}

void Sweeper::testHeader(libnet_ptag_t header){
	if(header == -1){
		fprintf(stderr,
				"webspy::Sweeper: "
				"[ERRO] LibNet error: "
				"error on mount header: %s"
				, libnet_geterror(WebSpyGlobals::context));
		exit(EXIT_FAILURE);
	}
}

void Sweeper::configARPSniffer(){
	if(pcap_lookupnet(WebSpyGlobals::iface, &ip, &netMask, pcapErrBuffer) == -1){
		fprintf(stderr,
				"webspy::Sweeper: "
				"[WARN] pCap warning: "
				"couldn't get interface %s netmask and IP\n",
				pcapErrBuffer);
		netMask = 0;
		ip = 0;
	}

	pcapContext = pcap_open_live(WebSpyGlobals::iface, BUFSIZ, 1, 1000, pcapErrBuffer);
	if(pcapContext == NULL){
		fprintf(stderr,
				"webspy::Sweepr: "
				"[ERRO] pCap error: "
				"couldn't open device %s: %s",
				WebSpyGlobals::iface, pcapErrBuffer);
		exit(EXIT_FAILURE);
	}

	if(pcap_compile(pcapContext, &filter, "arp", 0, netMask)){
		fprintf(stderr, "webspy::Sweeper: [ERRO] pCap error: couldn't compile arp filter: %s", pcapErrBuffer);
		exit(EXIT_FAILURE);
	}

	if(pcap_setfilter(pcapContext, &filter) == -1){
		fprintf(stderr, "webspy::Sweeper: [ERRO] pCap error: couldn't apply arp filter: %s", pcapErrBuffer);
		exit(EXIT_FAILURE);
	}
}
