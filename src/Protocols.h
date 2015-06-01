/*
 * Protocols.h
 *
 *  Created on: 21/05/2015
 *      Author: rodopoulos
 */

#ifndef PROTOCOLS_H_
#define PROTOCOLS_H_

#include <pcap.h>
#include <libnet.h>

struct ARP{
	uint16_t	htype;
	uint16_t	ptype;
	uint8_t		hsize;
	uint8_t		psize;
	uint16_t	arpOp;
	uint8_t		shaddr[6];
	uint32_t	spaddr;
	uint8_t		thaddr[6];
	uint32_t	tpaddr;
	ARP(unsigned char* buf);
	uint16_t getOperation();
};

struct Ethernet{
	uint8_t		thaddr[6];	/* Target MAC Address */
	uint8_t		shaddr[6];	/* Sender MAC Address */
	uint16_t	ptype;		/* Protocol type */
	Ethernet(unsigned char* buf);
	uint16_t getType();
	const char* getTypeName();
};


#endif /* PROTOCOLS_H_ */
