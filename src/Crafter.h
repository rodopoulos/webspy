/*
 * Crafter.h
 *
 *  Created on: 21/05/2015
 *      Author: rodopoulos
 */

#ifndef SRC_CRAFTER_H_
#define SRC_CRAFTER_H_

#define LIBNET_ERROR 		-1

#define CRAFTER_ARP			1
#define CRAFTER_ETHERNET	2
#define CRAFTER_IP			3
#define CRAFTER_TCP			4
#define CRAFTER_UDP			5
#define CRAFTER_DNS			6

#include <libnet.h>
#include <map>

class Crafter {
	libnet_t* 						context;
	char							errorBuffer[LIBNET_ERRBUF_SIZE];
	std::map<int, libnet_ptag_t>	protocols;

	void error(char* method);

public:
	static uint8_t broadcastMAC[6];
	static uint8_t zeroMAC[6];

	Crafter();
	Crafter(const char* iface);
	virtual ~Crafter();

	void send();
	void clear();
	void close();

	void arp(uint16_t op, uint8_t smac[], uint32_t sip, uint8_t tmac[], uint32_t tip);
	void ethernet(uint16_t op, uint8_t smac[], uint8_t tmac[]);
	// void ip();

};

#endif /* SRC_CRAFTER_H_ */
