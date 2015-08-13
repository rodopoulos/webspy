/*
 * Globals.h
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <iostream>
#include <string>

#include <tins/tins.h>
#include "Host.h"

class Globals {

public:
	Globals();
	virtual ~Globals();

	static bool logging;
	static bool verbose;
	static bool automatic;
	static Tins::NetworkInterface iface;
	static std::string ifaceRef;
	static Host attacker;
	static Host gateway;
	static Host victim;

	static void init();
	static void setInterface(std::string str);
	static std::string getGatewayIP();

};


#endif /* GLOBALS_H_ */
