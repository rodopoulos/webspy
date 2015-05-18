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
#include "Sniffer.h"
#include "ARPCrafter.h"
#include "EtherCrafter.h"

#define ARP_REQUEST 1
#define ARP_REPLY 	2

class Sweeper {
private:
	typedef struct arpPacket_t{
		uint16_t 	htype;    	  /* Hardware Type           */
		uint16_t 	ptype;    	  /* Protocol Type           */
		uint8_t		hlen;         /* Hardware Address Length */
		uint8_t 	plen;         /* Protocol Address Length */
		uint16_t 	oper;     	  /* Operation Code          */
		uint8_t		senderMAC[6]; /* Sender hardware address */
		uint8_t		senderIP[4];  /* Sender IP address       */
		uint8_t		targetMAC[6]; /* Target hardware address */
		uint8_t		targetIP[4];  /* Target IP address       */
	} arpPacket;

	void configARPSniffer();
	void testHeader(libnet_ptag_t header);

public:
	Sweeper();
	virtual ~Sweeper();

	std::vector<Host> sweep();
};

#endif /* SWEEPER_H_ */
