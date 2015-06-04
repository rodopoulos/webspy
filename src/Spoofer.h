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
#include <pthread.h>

#include "Globals.h"
#include "Protocols.h"
#include "Host.h"
#include "Crafter.h"
#include "Sniffer.h"

class Spoofer {
	static void* spoof(void* args);
	static void spoofBack(u_char* args, const struct pcap_pkthdr* header, const unsigned char* packet);

public:
	Spoofer();
	virtual ~Spoofer();

	void init();
};

#endif /* SPOOFER_H_ */
