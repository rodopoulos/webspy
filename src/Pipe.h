/*
 * Pipe.h
 *
 *  Created on: 01/06/2015
 *      Author: rodopoulos
 */

#ifndef PIPE_H_
#define PIPE_H_

#include "Host.h"
#include "Sniffer.h"

class Pipe {
	Sniffer	sniffer;
public:
	Pipe(Host src, Host dst);
	virtual ~Pipe();
};

#endif /* PIPE_H_ */
