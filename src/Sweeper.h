/*
 * Sweeper.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef SWEEPER_H_
#define SWEEPER_H_

#include <string>
#include <vector>
#include "Host.h"

class Sweeper {

public:
	Sweeper();
	virtual ~Sweeper();

	std::vector<Host> sweep();
};

#endif /* SWEEPER_H_ */
