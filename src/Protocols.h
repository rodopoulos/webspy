/*
 * Protocols.h
 *
 *  Created on: 21/05/2015
 *      Author: rodopoulos
 */

#ifndef PROTOCOLS_H_
#define PROTOCOLS_H_

#include <sstream>
#include <cstring>
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
	int getHdrLen();
};

struct TCP{
	uint16_t sport;
	uint16_t dport;
	uint32_t seqid;
	uint32_t ack;
	uint8_t  hlen;
	uint8_t  flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgptr;

	TCP(unsigned char* buf);
	int getHdrLen();
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
};

class HTTP{
#define HTTP_REQ 		 1
#define HTTP_RES 		 2
#define HTTP_T_HTML 	 1
#define HTTP_T_JS		 2
#define HTTP_T_CSS		 3
#define HTTP_T_IMG		 4
#define HTTP_T_JSDATA	 5
#define HTTP_T_NONE 	 6

public:
	char*		data;
	uint32_t	srvAddr;
	uint16_t	srvPort;
	int 		len;
	int			op;

	std::string	host, referer;
	std::string	path;
	int 		contentLenght;
	int			contentType;

	HTTP(uint32_t srvAddr, uint16_t srvPort, unsigned char* payload);
	static std::string retrieveHeaderValue(unsigned char* data, char* key);
	static std::string retrieveObjectPath(unsigned char* data);
	static int		   readMethod(char* payload);
	static int		   getContentTypeCode(std::string type);


	void 		setResponseContent(unsigned char* content, int len);
	void 		setNoCache();
	void 		setNoCookieEncoding();

	void  stripSSL();

};


#endif /* PROTOCOLS_H_ */
