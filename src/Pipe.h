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

#include "Host.h"
#include "Protocols.h"
#include "Sniffer.h"
#include "Crafter.h"

struct pipeListenerArgs{
	Host* 	 src;
	Host* 	 dst;
	Sniffer* sniffer;
	Crafter* crafter;
};

class Pipe {
	Host&		src, dst;
	pthread_t   thread;
	pthread_mutex_t victimMutex, gatewayMutex;

	static void* connect(void* args);
	static void  relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet);
	static void* routeToVictim(void* args);
	static void* routeToGateway(void* args);
	static void strip();

public:
	Pipe(Host& src, Host& dst);
	virtual ~Pipe();
	void init();
};

#endif /* PIPE_H_ */
