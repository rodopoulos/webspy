/*
 * Packet.h
 *
 *  Created on: 10 de jul de 2015
 *      Author: rodopoulos
 */

#ifndef SRC_PACKET_H_
#define SRC_PACKET_H_

#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>

#include "Protocols.h"

class Packet {
public:
	int len;
	const unsigned char* data;
	Ethernet* ethernet;
	IP*		  ip;
	TCP*	  tcp;

	Packet(const unsigned char* data, int len);
	virtual ~Packet();

	TCP* getTCP();
	int getHdrLen();
	int getPayloadLen();
	unsigned char* getPayload();
	bool isTCPSegment();
	bool isHTTP();

};

#endif /* SRC_PACKET_H_ */
