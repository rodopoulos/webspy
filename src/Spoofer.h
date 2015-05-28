/*
 * Spoofer.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef SPOOFER_H_
#define SPOOFER_H_

#include <libnet.h>
#include <pcap.h>
#include <cstdio>
#include <string>

#include "Globals.h"
#include "Protocols.h"
#include "Host.h"
#include "Crafter.h"
#include "Sniffer.h"

class Spoofer {

public:
	Spoofer();
	virtual ~Spoofer();

	void spoof();
	static void spoofBack(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet);
	static void hexDump(const unsigned char* buf, int iByte, int lByte);
};

#endif /* SPOOFER_H_ */
