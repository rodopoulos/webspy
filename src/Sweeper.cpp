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
libnet_ptag_t		Sweeper::etherHeader;

// Constructors --------------------------------------------------------------
Sweeper::Sweeper(){ }

Sweeper::~Sweeper(){ }

// Public --------------------------------------------------------------
vector<Host> Sweeper::sweep(){
	printf("\n== INITING SWEEP ==\n");
	Sniffer arpSniffer("arp");
	printf("\nARP Sniffing is on...\n");
	printf("Starting to send ARP Requests...\n\n");

	uint32_t currentIp = (uint32_t)(arpSniffer.ip);
	uint32_t range = ~(uint32_t)(arpSniffer.mask);
	range = (range >> 24) + (range << 8 >> 16 ) + (range << 16 >> 8) + (range << 24) + 1;
	printf("LAN IP: %s\n", Host::ipToString(currentIp).c_str());
	printf("Net mask: %s\n", Host::ipToString((arpSniffer.mask)).c_str());
	printf("Number of probes: %u\n", range);

	ARPCrafter arpCrafter(WebSpyGlobals::context);

	vector<Host> tmp;
	uint32_t i;
	for(i = 0; i < range; i++){
		printf("Probing host on %s ...\n", Host::ipToString(currentIp).c_str());
		currentIp += 1 << 24; // Iterando um IP em little endian
	}

	return tmp;
}

