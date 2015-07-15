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
Crafter Sweeper::crafter(Globals::iface);

/************************************************************************
 * * * * * * * * CONSTRUCTORS * * * * * * * * * * * * * * * * * * * * * *
 ************************************************************************/
Sweeper::Sweeper(){ }


Sweeper::~Sweeper(){ }


/************************************************************************
 * * * * * * * * ACTIONS * * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
vector<Host>& Sweeper::sweep(){
	char filter[] = "arp";
	Sniffer arpSniffer(filter);
	arpSniffer.setTimeout(5000);
	if(Globals::verbose)
		arpSniffer.showLANProps();

	struct probingArgs arguments;
	arguments.initial = (uint32_t)(arpSniffer.lan);
	arguments.range   = ~htonl(arpSniffer.mask);
	arguments.sniffer = &arpSniffer;

	pthread_t probingThread;
	if(pthread_create(&probingThread, NULL, sendProbes, &arguments)){
		fprintf(stderr, "Webspy::Sweeper::sweep > [ERRO] can't create probing thread");
		exit(EXIT_FAILURE);
	}

	arpSniffer.listen(arpReplyFilter);

	int nHosts = avaiableHosts.size();
	printf("%d %s found.\n", nHosts, nHosts <= 1 ? "host" : "hosts");
	return avaiableHosts;
}

void* Sweeper::sendProbes(void* args){
	probingArgs *arguments = (probingArgs*) args;

	Crafter crafter(Globals::iface);
	crafter.arp(ARPOP_REQUEST, Globals::attacker.mac->ether_addr_octet, Globals::attacker.ip, Crafter::zeroMAC, arguments->initial);
	crafter.ethernet((uint16_t)ETHERTYPE_ARP, Globals::attacker.mac->ether_addr_octet, Crafter::broadcastMAC);

	printf("ARP Sweep: sending %u ARP Requests...\n", arguments->range);
	uint32_t i;
	uint32_t initial = htonl(arguments->initial);
	for(i = 1; i <= arguments->range; i++){
		uint32_t curr = ntohl(initial + i);
		if(curr != Globals::attacker.ip){

			if(Globals::verbose)
				printf("  Probing host on %s ...\n", Host::ipToString(curr).c_str());

			crafter.send();
			crafter.arp(
				ARPOP_REQUEST,
				Globals::attacker.mac->ether_addr_octet,
				Globals::attacker.ip,
				Crafter::zeroMAC,
				curr
			);
		}
	}
	sleep(5);

	int count = 0;
	if(Globals::gateway.ip){
		while(Globals::gateway.mac == NULL && count < 5){
			printf("Sem MAC do gateway... aguardando.\n");
			sendARPRequest(Globals::gateway.ip);
			sleep(1);
			count++;
		}
	}

	arguments->sniffer->breakLoop();
	return NULL;
}

void Sweeper::arpReplyFilter(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	Ethernet etherHeader((unsigned char*)packet);

	if(htons(etherHeader.ptype) == ETHERTYPE_ARP){
		ARP arpPacket((unsigned char*)packet);
		if(htons(arpPacket.arpOp) == ARPOP_REPLY){
			if(arpPacket.spaddr == Globals::gateway.ip){
				Globals::gateway.setMAC(arpPacket.shaddr);
				if(Globals::verbose){
					printf(
						"  Gateway with MAC %s responded for IP %s\n",
						Host::macToString(arpPacket.shaddr).c_str(),
						Host::ipToString(arpPacket.spaddr).c_str()
					);
				}
				return;
			} else if(!hasHostIP(avaiableHosts, arpPacket.spaddr)
					&& arpPacket.spaddr != Globals::attacker.ip){
				Host newHost(arpPacket.spaddr, arpPacket.shaddr, "");
				avaiableHosts.push_back(newHost);
				if(Globals::verbose){
					printf(
						"  Host with MAC %s responded for IP %s (%s)\n",
						Host::macToString(arpPacket.shaddr).c_str(),
						Host::ipToString(arpPacket.spaddr).c_str(),
						Host::getMACVendor(arpPacket.shaddr)
					);
				}
				return;
			} // else -> não é pra mim
		} // else -> não é Reply
	} // else -> não é ARP
}

void Sweeper::sendARPRequest(uint32_t ip){
	crafter.arp(ARPOP_REQUEST, Globals::attacker.mac->ether_addr_octet, Globals::attacker.ip, Crafter::zeroMAC, ip);
	crafter.ethernet((uint16_t)ETHERTYPE_ARP, Globals::attacker.mac->ether_addr_octet, Crafter::broadcastMAC);
	crafter.send();
	if(Globals::verbose)
		printf("  Probed host on %s ...\n", Host::ipToString(ip).c_str());
}



/************************************************************************
 * * * * * * * * UTILS * * * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/

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

void Sweeper::findHostMAC(Host* host){
	Crafter crafter(Globals::iface);
	crafter.arp(ARPOP_REQUEST, Globals::attacker.mac->ether_addr_octet, Globals::attacker.ip, Crafter::zeroMAC, host->ip);
	crafter.ethernet((uint16_t)ETHERTYPE_ARP, Globals::attacker.mac->ether_addr_octet, Crafter::broadcastMAC);

	char filter[] = "arp";
	Sniffer arpSniffer(filter);
	arpSniffer.setDirection(PCAP_D_IN);

	printf("ARP Request to host on %s ... ", Host::ipToString(host->ip).c_str());
	crafter.send();
	sleep(1);

	const unsigned char* packet;
	int loops;
	do{
		packet = arpSniffer.nextPacket();
		if(packet){
			Ethernet etherHeader((unsigned char*) packet);
			if(htons(etherHeader.ptype) == ETHERTYPE_ARP){
				ARP arpPacket((unsigned char*)packet);
				if(htons(arpPacket.arpOp) == ARPOP_REPLY){
					if(host->ip == arpPacket.spaddr){
						host->setMAC(arpPacket.shaddr);
						printf("found with MAC %s\n", Host::macToString(host->mac).c_str());
						return;
					}
				}
			}
		}
		loops++;
	} while(loops != 5);
	printf("not found\n");
}

