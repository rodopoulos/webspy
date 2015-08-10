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
#include <nids.h>
#include <queue>
#include "Host.h"
#include "Sniffer.h"
#include "Crafter.h"
#include "Renderer.h"
#include "Protocols.h"
#include "HTTPSession.h"
#include "TCPAssembler.h"

class Pipe {
	pthread_t snifferThread, analyserThread;

	static long packetCount;
	static TCPAssembler assembler;
	static pthread_t assemblerThread;
	static pthread_mutex_t analyserMutex;
	static Crafter crafter;
	static std::queue<Packet> analyseBuffer;
	static Renderer* renderer;

	static void* connect(void* args);
	static void* initAssembler(void* args);
	static void  relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* rcvdPacket);
	static void* routeToVictim(void* args);
	static void* routeToGateway(void* args);
	static void* analyseHTTP(void* args);

public:
	Pipe();
	virtual ~Pipe();
	void init(Renderer* rendererPtr);
};

#endif /* PIPE_H_ */
