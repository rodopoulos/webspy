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

struct IP{
	uint8_t	 version:4, hl:4;
	uint8_t  tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint32_t src;
	uint32_t dst;
};

struct TCP{
	uint16_t srcport;
	uint16_t dstport;
	uint32_t seqid;
	uint32_t ackid;
	uint8_t offset:4, rsvd:4;
	uint8_t cwr:1, ece:1, urg:1, ack:1, psh:1, syn:1, fin:1;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgptr;
};

struct HTML{
	uint8_t	method;
	uint8_t ver;
	uint8_t datatype;
	char* url;
};


#endif /* PROTOCOLS_H_ */
