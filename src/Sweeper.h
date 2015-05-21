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

#include "WebSpyGlobals.h"
#include "Host.h"
#include "Sniffer.h"
#include "ARPCrafter.h"
#include "EtherCrafter.h"


class Sweeper {
private:

	void configARPSniffer();
	void testHeader(libnet_ptag_t header);

public:
	Sweeper();
	virtual ~Sweeper();

	std::vector<Host> sweep();
	bool hasHostIP(std::vector<Host>, uint32_t);
	void hexDump(const unsigned char* buf, int iByte, int lByte);
	void arpReplyHandler(u_char *args, const struct pcap_pkthdr* header, const unsigned char* packet);
};

#endif /* SWEEPER_H_ */
