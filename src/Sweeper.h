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
#include <cmath>
#include <libnet.h>
#include <pcap.h>

#include "Host.h"

class Sweeper {
private:
	static pcap_t* 			pcapContext;
	static char				pcapErrBuffer[PCAP_ERRBUF_SIZE];
	static bpf_u_int32		netMask;

	static libnet_ptag_t	arpHeader;
	static libnet_ptag_t	etherHeader;

	static bpf_u_int32			ip;
	static struct bpf_program 	filter;

	void configARPSniffer();
	void testHeader(libnet_ptag_t header);

public:
	Sweeper();
	virtual ~Sweeper();

	std::vector<Host> sweep();
};

#endif /* SWEEPER_H_ */
