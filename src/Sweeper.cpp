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


uint8_t Sweeper::zeroedMac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
uint8_t Sweeper::broadcastMac[6] = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

Sweeper::Sweeper(){ }

Sweeper::~Sweeper(){ }

vector<Host> Sweeper::sweep(){
	printf("\n== INITING SWEEP ==\n");
	configARPSniffer();
	printf("Network: %s\n", "IP");
	printf("Mask: %d\n", "oi");
	printf("\nARP Sniffing is on...\n");
	printf("Starting to send ARP Requests...\n\n");

	printf("Mounting ARP Header........ ");
	//craftARPHeader();
	printf("OK\n");

	printf("Mounting Ethernet Header... ");
	//craftEtherHeader();
	printf("OK\n");

	/* Montando os cabeçalhos dos ARP Requests
	arpHeader = libnet_autobuild_arp(ARPOP_REQUEST,
			WebSpyGlobals::attacker.getMac()->ether_addr_octet, WebSpyGlobals::attacker.getIP(),
			currentIp, Sweeper::zeroedMac,
			WebSpyGlobals::context);
	testHeader(arpHeader);*/

	etherHeader = libnet_autobuild_ethernet(Sweeper::broadcastMac,
			ETHERTYPE_ARP,
			WebSpyGlobals::context);
	testHeader(etherHeader);

	vector<Host> tmp;
	int hostCount=0;
	uint32_t currentIp;
	for(;;){


		libnet_write(WebSpyGlobals::context);
	}

	pcap_close(Sweeper::pcapContext);
	libnet_clear_packet(WebSpyGlobals::context);
	return tmp;
}

void Sweeper::testHeader(libnet_ptag_t header){
	/*if(header == -1){
		fprintf(stderr,
				"webspy::Sweeper: "
				"[ERRO] LibNet error: "
				"error on mount header: %s"
				, libnet_geterror(WebSpyGlobals::context));
		exit(EXIT_FAILURE);
	}*/
}

void Sweeper::configARPSniffer(){
	/*if(pcap_lookupnet(WebSpyGlobals::iface, &ip, &netMask, pcapErrBuffer) == -1){
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
	}*/
}
