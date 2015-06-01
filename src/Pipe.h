/*
 * Pipe.h
 *
 *  Created on: 01/06/2015
 *      Author: rodopoulos
 */

#ifndef PIPE_H_
#define PIPE_H_

#include <pcap.h>
#include <pthread.h>

#include "Host.h"
#include "Protocols.h"
#include "Sniffer.h"

class Pipe {
	Sniffer		sniffer;
	Host&		src, dst;
	pthread_t   thread;

	static void* listeningPackets(void* pipe);
	static void relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet);

public:
	Pipe(Host& src, Host& dst);
	virtual ~Pipe();
};

#endif /* PIPE_H_ */
