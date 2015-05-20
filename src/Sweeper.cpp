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
	arpSniffer.showLANProps();

	uint32_t currentIp = (uint32_t)(arpSniffer.lan);

	ARPCrafter arpCrafter(WebSpyGlobals::context);
	EtherCrafter etherCrafter(WebSpyGlobals::context);
	arpCrafter.newARP(ARPOP_REQUEST, WebSpyGlobals::attacker.mac, WebSpyGlobals::attacker.ip, EtherCrafter::zeroedMac, currentIp);
	etherCrafter.newEther(WebSpyGlobals::attacker.mac, EtherCrafter::broadcastMac, (uint16_t)ETHERTYPE_ARP);

	unsigned int i;
	vector<Host> tmp;
	uint32_t range = ~htonl(arpSniffer.mask);
	printf("\nSending %u ARP Requests. Starting...\n", range);
	for(i = 0; i < range; i++){
		currentIp = ntohl((htonl(currentIp) + 1)); 		// Iterando um IP em little endian

		if(currentIp != WebSpyGlobals::attacker.ip){
			printf("    Probing host on %s ... ", Host::ipToString(currentIp).c_str());
			const unsigned char* buffer;

			libnet_write(WebSpyGlobals::context); 	  	// Send
			buffer = arpSniffer.nextPacket();   		// Listen

			if(buffer){
				ARPPacket arpReply((unsigned char*)buffer);
				if(Host::isSameMAC(arpReply.thaddr, WebSpyGlobals::attacker.mac->ether_addr_octet)){
					if(ntohs(arpReply.arpOp) == ARPOP_REPLY){
						printf("response with MAC %s (with IP %s)\n", Host::macToString(arpReply.shaddr).c_str(), Host::ipToString(arpReply.spaddr).c_str());
						Host newHost(arpReply.spaddr, arpReply.shaddr, "");
						tmp.push_back(newHost);
					} else {
						printf("ARP frame, but it's not reply\n");
					}
				} else {
					printf("ARP frame, but not for host\n");
				}
			} else {
				printf("no response at all\n");
			}
			arpCrafter.setTargetIP(currentIp);
		}
		// getchar();
	}

	printf("Respostas: %d\n", tmp.size());
	return tmp;
}

void Sweeper::hexDump(const unsigned char* buf, int iByte, int lByte){
	int i, j = 1;
	printf("\nPacket hex dump (byte offset %d - %d): \n", iByte, lByte);
	for(i = iByte; i < lByte; i++){
		printf("%02x ", buf[i]);
		if(j == 4){
			j = 0;
			printf("\n");
		}
		j++;
	}
	printf("\n\n");
}
