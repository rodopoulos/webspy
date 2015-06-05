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

struct pipeListenerArgs{
	Host* 	 src;
	Host* 	 dst;
	Sniffer* sniffer;
};

class Pipe {
	Host&		src, dst;
	pthread_t   thread;

	static void* connect(void* args);
	static void relay(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet);

public:
	Pipe(Host& src, Host& dst);
	virtual ~Pipe();
	void init();
};

#endif /* PIPE_H_ */
