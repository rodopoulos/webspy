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

vector<Host> Sweeper::avaiableHosts;

// Constructors --------------------------------------------------------------
Sweeper::Sweeper(){ }

Sweeper::~Sweeper(){ }

// Public --------------------------------------------------------------
vector<Host>& Sweeper::sweep(){
	char filter[] = "arp";
	Sniffer arpSniffer(filter);
	arpSniffer.setTimeout(5000);
	if(Globals::verbose)
		arpSniffer.showLANProps();

	uint32_t currentIp = (uint32_t)(arpSniffer.lan);

	Crafter crafter(Globals::iface);
	crafter.arp(ARPOP_REQUEST, Globals::attacker.mac->ether_addr_octet, Globals::attacker.ip, Crafter::zeroMAC, currentIp);
	crafter.ethernet((uint16_t)ETHERTYPE_ARP, Globals::attacker.mac->ether_addr_octet, Crafter::broadcastMAC);

	unsigned int i;
	vector<Host> tmp;
	uint32_t range = ~htonl(arpSniffer.mask);
	printf("\nSending %u ARP Requests. Starting...\n", range);

	for(i = 0; i < range; i++){
		currentIp = ntohl((htonl(currentIp) + 1)); 		// Iterando um IP em little endian

		if(currentIp != Globals::attacker.ip){
			if(Globals::verbose)
				printf("  Probing host on %s ...\n", Host::ipToString(currentIp).c_str());

			crafter.send();
			arpSniffer.listenWithTimeout(arpReplyFilter);

			crafter.arp(ARPOP_REQUEST, Globals::attacker.mac->ether_addr_octet, Globals::attacker.ip, Crafter::zeroMAC, currentIp);
		}
	}

	int nHosts = avaiableHosts.size();
	printf("%d %s found.\n", nHosts, nHosts <= 1 ? "host" : "hosts");
	return avaiableHosts;
}

void Sweeper::arpReplyFilter(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	pcap_t* pcapContext = (pcap_t*)args;
	Ethernet etherHeader((unsigned char*)packet);

	if(htons(etherHeader.ptype) == ETHERTYPE_ARP){
		ARP arpPacket((unsigned char*)packet);
		if(htons(arpPacket.arpOp) == ARPOP_REPLY){
			if(arpPacket.spaddr == Globals::gateway.ip){
				Globals::gateway.setMAC(arpPacket.shaddr);
				printf(
					"  Gateway with MAC %s responded for IP %s\n",
					Host::macToString(arpPacket.shaddr).c_str(),
					Host::ipToString(arpPacket.spaddr).c_str()
				);
				pcap_breakloop(pcapContext);
			} else if(!hasHostIP(avaiableHosts, arpPacket.spaddr)
					&& arpPacket.spaddr != Globals::attacker.ip){
				Host newHost(arpPacket.spaddr, arpPacket.shaddr, "");
				avaiableHosts.push_back(newHost);
				printf(
					"  Host with MAC %s responded for IP %s\n",
					Host::macToString(arpPacket.shaddr).c_str(),
					Host::ipToString(arpPacket.spaddr).c_str()
				);
				pcap_breakloop(pcapContext);
				return;
			} else {
				// Nao eh pra mim
			}
		} else{
			// Nao eh Reply
		}
	} else {
		// Nao eh ARP
	}
	usleep(1000);
}

bool Sweeper::hasHostIP(vector<Host> hosts, uint32_t ip){
	vector<Host>::iterator it;
	for(it = hosts.begin(); it != hosts.end(); it++){
		if(it->ip == ip)
			return true;
	}
	return false;
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
