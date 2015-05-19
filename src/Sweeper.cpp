/*
 * Sweeper.cpp
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#include <iostream>

// this
#include "Sweeper.h"

using namespace std;

// Constructors --------------------------------------------------------------
Sweeper::Sweeper(){ }

Sweeper::~Sweeper(){ }

// Public --------------------------------------------------------------
vector<Host> Sweeper::sweep(){
	printf("\n========================== INITING SWEEP ============================\n");
	Sniffer arpSniffer("arp");
	printf("\nARP Sniffing is on...\n\n");

	uint32_t currentIp = (uint32_t)(arpSniffer.lan);
	printf("=== LAN Config ===\n");
	printf("IP Space: %s\n", Host::ipToString(currentIp).c_str());
	printf("Mask: %s\n", Host::ipToString((arpSniffer.mask)).c_str());
	printf("Link type: %s\n", arpSniffer.getLinkName());

	ARPCrafter arpCrafter(WebSpyGlobals::context);
	EtherCrafter etherCrafter(WebSpyGlobals::context);
	arpCrafter.newARP(ARPOP_REQUEST, WebSpyGlobals::attacker.mac, WebSpyGlobals::attacker.ip, EtherCrafter::zeroedMac, currentIp);
	etherCrafter.newEther(WebSpyGlobals::attacker.mac, EtherCrafter::broadcastMac, (uint16_t)ETHERTYPE_ARP);

	uint32_t range = ~(uint32_t)(arpSniffer.mask);
	range = (range >> 24) + (range << 8 >> 16 ) + (range << 16 >> 8) + (range << 24) + 1;

	vector<Host> tmp;
	unsigned int i;
	const unsigned char* packetBuffer;
	ARPCrafter::arp_pkt* arpReply;

	printf("\nStarting to send ARP Requests...\n");
	printf("Number of probes: %u\n", range);
	for(i = 0; i < range; i++){
		printf("    Probing host on %s ... ", Host::ipToString(currentIp).c_str());

		libnet_write(WebSpyGlobals::context); 	  // Send
		packetBuffer = arpSniffer.nextPacket();   // Listen

		if(packetBuffer){
			arpReply = LIBNET_ETH_H + (ARPCrafter::arp_pkt*) packetBuffer;
			printf("response with MAC \n");
			printf("\tPacote recebido: %s (%d)\n", ARPCrafter::getARPOperationName(ntohs(arpReply->arpOp)), arpReply->spaddr);
		} else {
			printf("timeout\n");
		}
		getchar();
		currentIp += 1 << 24; // Iterando um IP em little endian
		arpCrafter.setTargetIP(currentIp);
	}

	return tmp;
}

/* HEX DUMP
 *
 * int i, j = 1;
		printf("\nPacote: \n");
		for(i = 14; i < 42; i++){
			printf("%02x ", packetBuffer[i]);
			if(j == 4){
				j = 0;
				printf("\n");
			}
			j++;
		}
		printf("\n");
 * */
