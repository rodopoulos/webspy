/*
 * Pipe.h
 *
 *  Created on: 01/06/2015
 *      Author: rodopoulos
 */

#ifndef PIPE_H_
#define PIPE_H_
#define XORSWAP(a, b)	((a)^=(b),(b)^=(a),(a)^=(b))

#include <pcap.h>
#include <pthread.h>

#include <queue>
#include "Host.h"
#include "Protocols.h"
#include "Sniffer.h"
#include "Crafter.h"

class Pipe {
	pthread_t snifferThread, victimThread, gatewayThread;
	static pthread_mutex_t victimMutex, gatewayMutex;
	static Crafter victimCrafter, gatewayCrafter;
	static std::queue<Packet> gatewayBuffer, victimBuffer;

	static void* connect(void* args);
	static void  relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet);
	static void* routeToVictim(void* args);
	static void* routeToGateway(void* args);
	static Packet strip(Packet packet);

public:
	Pipe();
	virtual ~Pipe();
	void init();
};

#endif /* PIPE_H_ */
