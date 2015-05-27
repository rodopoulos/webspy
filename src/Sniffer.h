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

#include "Globals.h"
#include "Host.h"

class Sniffer {

private:
	pcap_t* 			pcapContext;
	int					linkType;
	int					linkHrdLen;
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


	const unsigned char* nextPacket();
	void listen(pcap_handler callback);
	void listen(pcap_handler callback, int packets);
	void listenWithTimeout(pcap_handler callback);

	void close();
	void setLinkHrdLen(int linkType);
	void setTimeout(int time);

	const char* getLinkName();
	void showLANProps();
};

#endif /* SNIFFER_H_ */
