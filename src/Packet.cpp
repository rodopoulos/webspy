/*
 * Packet.cpp
 *
 *  Created on: 10 de jul de 2015
 *      Author: rodopoulos
 */

#include "Packet.h"

Packet::Packet(const unsigned char* data, int len) {
	this->len = len;
	this->data = (const unsigned char*) malloc(len * sizeof(const unsigned char*));
	memcpy(this->data, data, len);
}

Packet::~Packet() {}

