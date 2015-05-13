/*
 * Sweeper.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef SWEEPER_H_
#define SWEEPER_H_

#include <string>
#include <vector>
#include <pcap.h>
#include <libnet.h>

#include "Host.h"

class Sweeper {
private:
	static pcap_t* 			pcapContext;
	static char				pcapErrBuffer[PCAP_ERRBUF_SIZE];
	static bpf_u_int32			netMask;
	static bpf_u_int32			ip;
	static struct bpf_program 	filter;

	libnet_ptag_t	arpHeader;
	libnet_ptag_t	etherHeader;

	static uint8_t zeroedMac[6];
	static uint8_t broadcastMac[6];

	void configARPSniffer();
	void testHeader(libnet_ptag_t header);

public:
	Sweeper();
	virtual ~Sweeper();

	std::vector<Host> sweep();
};

#endif /* SWEEPER_H_ */
