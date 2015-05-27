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

#include "Globals.h"
#include "Host.h"
#include "Crafter.h"
#include "Sniffer.h"
#include "Protocols.h"


class Sweeper {
private:

	void configARPSniffer();
	void testHeader(libnet_ptag_t header);

public:
	Sweeper();
	virtual ~Sweeper();

	static std::vector<Host> avaiableHosts;

	std::vector<Host>& sweep();
	static bool hasHostIP(std::vector<Host>, uint32_t);
	static void arpReplyFilter(u_char *args, const struct pcap_pkthdr* header, const unsigned char* packet);

	static void hexDump(const unsigned char* buf, int iByte, int lByte);
};

#endif /* SWEEPER_H_ */
