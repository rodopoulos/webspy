/*
 * Sweeper.cpp
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#include "Sweeper.h"

using namespace Tins;

std::vector<Host> Sweeper::hosts;

Sweeper::Sweeper() {}
Sweeper::~Sweeper() {}


void Sweeper::sweep(){
	pthread_t proberThread;
	if(pthread_create(&proberThread, nullptr, sendProbes, nullptr)){
		std::cerr << "\033[1;31m [Error]"
					 " Sweeper::sweep ->"
					 "\033[0m can't create thread for probing" << std::endl;
		exit(EXIT_FAILURE);
	}

	std::string filter = "arp";
	Sniffer sniffer(Globals::iface.name(), Sniffer::PROMISC, filter);
	sniffer.set_timeout(500);
	sniffer.sniff_loop(replyHandle);
}

Host& Sweeper::selectHost(){
	int opt, cont = 1;
	std::vector<Host>::iterator it;
	std::cout << " [#] "    << std::setw(5)
			  << "[IP]"     << std::setw(15)
			  << "[MAC]"    << std::setw(17)
			  << "[VENDOR]"
			  << std::endl;
	for(it = hosts.begin(); it != hosts.end(); it++){
		std::cout << cont << std::setw(5)
				  << (*it).ip.to_string()  << std::setw(15)
				  << (*it).mac.to_string() << std::setw(17)
				  << (*it).name;
		cont++;
	}
	std::cout << std::endl << "Select ID: ";
	std::cin >> opt;

	return hosts[opt];
}









void* Sweeper::sendProbes(void* args){
	IPv4Range range = IPv4Range::from_mask(
		baseIP(Globals::iface.info().ip_addr.to_string()),
		Globals::iface.info().netmask
	);

	IPv4Address  spaddr = Globals::attacker.ip;
	HWAddress<6> shaddr = Globals::attacker.mac;

	PacketSender sender(Globals::iface);
	for (const auto &target : range){
		if(target != Globals::attacker.ip && target != Globals::gateway.ip){
			EthernetII request = ARP::make_arp_request(target, spaddr, shaddr);
			sender.send(request);
		}
	}
	return nullptr;
}

bool Sweeper::replyHandle(PDU& reply){
	const ARP &arp = reply.rfind_pdu<ARP>();
	if(arp.opcode() == ARP::REPLY){
		if(isNewHost(arp.sender_ip_addr())){
			Host host(arp.sender_ip_addr(), arp.sender_hw_addr());
			hosts.push_back(host);
		}
	}
	return true;
}

bool Sweeper::isNewHost(IPv4Address ip){
	std::vector<Host>::iterator it;
	for(it = hosts.begin(); it != hosts.end(); it++){
		if((*it).ip == ip)
			return false;
	}
	return true;
}

std::string Sweeper::baseIP(std::string ip){
	std::size_t pos = ip.rfind('.');
	std::string base = ip.substr(0, pos);
	base.append(".0");

	return base;
}
