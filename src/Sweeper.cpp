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
	Sniffer arpSniffer("arp");
	if(WebSpyGlobals::verbose)
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
			if(WebSpyGlobals::verbose)
				printf("  Probing host on %s\n", Host::ipToString(currentIp).c_str());

			const unsigned char* buffer;
			libnet_write(WebSpyGlobals::context); 	  				// Send

			buffer = arpSniffer.nextPacket();
			do{
				ARPPacket arpReply((unsigned char*)buffer);
				if(Host::isSameMAC(arpReply.thaddr, WebSpyGlobals::attacker.mac->ether_addr_octet)){
					if(ntohs(arpReply.arpOp) == ARPOP_REPLY){
						if(!hasHostIP(tmp, arpReply.spaddr)){
							printf("  Host with MAC %s responded for IP %s!\n", Host::macToString(arpReply.shaddr).c_str(), Host::ipToString(arpReply.spaddr).c_str());
							Host newHost(arpReply.spaddr, arpReply.shaddr, "");
							tmp.push_back(newHost);
						}
					} else {
						if(WebSpyGlobals::verbose)
							printf("ARP frame for me, but it's not a reply\n");
					}
				} else {
					//printf("ARP frame (%s), but not for me\n", ARPCrafter::getARPOperationName(arpReply.arpOp));
					if(WebSpyGlobals::verbose)
						printf(" timeout.\n");
				}
				buffer = arpSniffer.nextPacket();
			} while(buffer);

			arpCrafter.setTargetIP(currentIp);
		}
	}

	printf("Respostas: %d\n", (int)tmp.size());
	return tmp;
}

bool Sweeper::hasHostIP(vector<Host> hosts, uint32_t ip){
	vector<Host>::iterator it;
	for(it = hosts.begin(); it != hosts.end(); it++){
		if(it->ip == ip)
			return true;
	}
	return false;
}

void Sweeper::arpReplyHandler(unsigned char* args, const pcap_pkthdr* header, const unsigned char* packet){
	/* testar ser o
	 * if(header->len < 42)
		return;
	*/
	printf("PACOTE (len: %d, caplen: %d\n", header->len, header->caplen);
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
