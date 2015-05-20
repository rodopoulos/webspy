/*
 * Sniffer.h
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_

#include <pcap.h>
#include <string>

#include "WebSpyGlobals.h"
#include "Host.h"

class Sniffer {

private:
	pcap_t* 			pcapContext;
	int					linkType;
	struct bpf_program 	filter;
	char				pcapErrBuffer[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr 	packet;

public:
	bpf_u_int32		mask;
	bpf_u_int32		lan;
	char*			filterExpression;

	Sniffer();
	Sniffer(char filter[]);
	virtual ~Sniffer();

	void showLANProps();

	const unsigned char* nextPacket();
	const char* getLinkName();
};

#endif /* SNIFFER_H_ */
