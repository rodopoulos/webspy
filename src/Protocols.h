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
	uint8_t	 versionAndHl;
	uint8_t  tos;
	uint16_t len;
	uint16_t id;
	uint16_t off;
	uint8_t  ttl;
	uint8_t  protocol;
	uint16_t checksum;
	uint32_t src;
	uint32_t dst;

	IP(unsigned char* buf);
};

struct TCP{
	uint16_t sport;
	uint16_t dport;
	uint32_t seqid;
	uint32_t ackid;
	uint8_t  offrsv;
	uint8_t  flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgptr;

	TCP(unsigned char* buf);
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
};

struct HTML{
	uint8_t	method;
	uint8_t ver;
	uint8_t datatype;
	char* url;
};


#endif /* PROTOCOLS_H_ */
