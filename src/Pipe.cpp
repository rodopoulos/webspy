/*
 * Pipe.cpp
 *
 *  Created on: 01/06/2015
 *      Author: rodopoulos
 */

#include "Pipe.h"

Pipe::Pipe() {
	sniffer("tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)");
}

Pipe::~Pipe() {
	// TODO Auto-generated destructor stub
}
