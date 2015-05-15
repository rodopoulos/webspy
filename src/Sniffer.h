/*
 * Sniffer.h
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_

#include <pcap.h>

#include "WebSpyGlobals.h"

class Sniffer {

private:
	pcap_t*				context;
	pcap_t* 			pcapContext;
	struct bpf_program 	filter;
	char				pcapErrBuffer[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr 	packet;

public:
	bpf_u_int32		mask;
	bpf_u_int32		lan;

	Sniffer();
	Sniffer(char* filter);
	virtual ~Sniffer();

	char* nextPacket();
};

#endif /* SNIFFER_H_ */
