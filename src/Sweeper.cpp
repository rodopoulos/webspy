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
	std::string filter = "arp";
	Sniffer sniffer(Globals::iface.name(), Sniffer::PROMISC, filter);
	sniffer.set_timeout(500);

	pthread_t snifferThread;
	pthread_create(&snifferThread, nullptr, initSniffer, &sniffer);

	sendProbes();
	sniffer.stop_sniff();
}

Host& Sweeper::selectHost(){
	int opt, cont = 1;
	if(hosts.empty()){
		std::cout << "\033[1;33m[WARNING]\033[0m"
				  << " No hosts found. Exiting..." << std::endl;
		exit(EXIT_SUCCESS);
	}
	std::vector<Host>::iterator it;
	std::cout << "\033[0;1m"<< std::endl
			  << "[ID]"     << std::setw(7)
			  << "[IP]"     << std::setw(15)
			  << "[MAC]"    << std::setw(23)
			  << "[VENDOR]" << "\033[0m" << std::endl;

	for(it = hosts.begin(); it != hosts.end(); it++){
		(*it).toString(cont);
		cont++;
	}
	std::cout << std::endl << "Select ID: ";
	std::cin >> opt;

	return hosts[opt - 1];
}









void Sweeper::sendProbes(){
	IPv4Range range = IPv4Range::from_mask(
		baseIP(Globals::iface.info().ip_addr.to_string()),
		Globals::iface.info().netmask
	);

	IPv4Address  spaddr = Globals::attacker.ip;
	HWAddress<6> shaddr = Globals::attacker.mac;

	PacketSender sender(Globals::iface);
	int count = 0;
	for (const auto &target : range){
		if(target != Globals::attacker.ip && target != Globals::gateway.ip){
			EthernetII request = ARP::make_arp_request(target, spaddr, shaddr);
			sender.send(request);
			count++;
		}
	}
	std::cout << "\033[0;1mARP Sweep: \033[0m" << count << " requests sended" << std::endl;
	sleep(5);

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

void* Sweeper::initSniffer(void* args){
	Sniffer* sniffer = (Sniffer*) args;
	sniffer->sniff_loop(replyHandle);
	return nullptr;
}
