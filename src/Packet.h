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

class Packet {
public:
	int len;
	const unsigned char* data;

	Packet(const unsigned char* data, int len);
	virtual ~Packet();
};

#endif /* SRC_PACKET_H_ */
