/*
 * Spoofer.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef SPOOFER_H_
#define SPOOFER_H_

#include "Host.h"

class Spoofer {

public:
	Spoofer(Host* victim);
	virtual ~Spoofer();
};

#endif /* SPOOFER_H_ */
