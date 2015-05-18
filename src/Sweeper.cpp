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

// Constructors --------------------------------------------------------------
Sweeper::Sweeper(){ }

Sweeper::~Sweeper(){ }

// Public --------------------------------------------------------------
vector<Host> Sweeper::sweep(){
	printf("\n== INITING SWEEP ==\n");
	Sniffer arpSniffer("arp");
	printf("\nARP Sniffing is on...\n");

	uint32_t currentIp = (uint32_t)(arpSniffer.lan);
	uint32_t range = ~(uint32_t)(arpSniffer.mask);
	range = (range >> 24) + (range << 8 >> 16 ) + (range << 16 >> 8) + (range << 24) + 1;
	printf("LAN IP: %s\n", Host::ipToString(currentIp).c_str());
	printf("Net mask: %s\n", Host::ipToString((arpSniffer.mask)).c_str());
	printf("Number of probes: %u\n", range);

	ARPCrafter arpCrafter(WebSpyGlobals::context);
	EtherCrafter etherCrafter(WebSpyGlobals::context);

	arpCrafter.newARP(ARPOP_REQUEST, WebSpyGlobals::attacker.mac, WebSpyGlobals::attacker.ip, ARPCrafter::zeroedMac, currentIp);
	etherCrafter.newEther(WebSpyGlobals::attacker.mac, EtherCrafter::zeroedMac, (uint16_t)ETHERTYPE_ARP);

	vector<Host> tmp;
	uint32_t i;
	//printf("Starting to send ARP Requests...\n\n");
	for(i = 0; i < range; i++){
		printf("Probing host on %s ...\n", Host::ipToString(currentIp).c_str());

		libnet_write(WebSpyGlobals::context); 	  // Send
		const unsigned char* packetBuffer;
		packetBuffer = arpSniffer.nextPacket();   // Listen
		libnet_arp_hdr* arpReply;
		arpReply = (struct libnet_arp_hdr*)packetBuffer + LIBNET_ETH_H;

		printf("Pacote recebido: %s\n", arpReply->ar_op == ARP_REPLY ? "ARP_REPLY" : "ARP_REQUEST");

		currentIp += 1 << 24; // Iterando um IP em little endian
	}

	return tmp;
}

