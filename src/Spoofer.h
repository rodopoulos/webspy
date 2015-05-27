/*
 * Spoofer.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef SPOOFER_H_
#define SPOOFER_H_

#include <libnet.h>
#include <cstdio>

#include "Globals.h"
#include "Crafter.h"

class Spoofer {

public:
	Spoofer();
	virtual ~Spoofer();

	void spoof();
};

#endif /* SPOOFER_H_ */
