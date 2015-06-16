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
#include <pthread.h>

#include "Globals.h"
#include "Host.h"
#include "Crafter.h"
#include "Sniffer.h"
#include "Protocols.h"

struct probingArgs{
	uint32_t initial;
	uint32_t range;
	Sniffer* sniffer;
};

class Sweeper {
	static std::vector<Host> avaiableHosts;
	static Crafter crafter;

	static void* sendProbes(void* args);
	static bool hasHostIP(std::vector<Host>, uint32_t);
	static void arpReplyFilter(u_char *args, const struct pcap_pkthdr* header, const unsigned char* packet);
	static void singleReplyFilter(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet);
	static void sendARPRequest(uint32_t ip);
	static void hexDump(const unsigned char* buf, int iByte, int lByte);

public:
	Sweeper();
	virtual ~Sweeper();

	std::vector<Host>& sweep();
	static void findHostMAC(Host* host);
};

#endif /* SWEEPER_H_ */
