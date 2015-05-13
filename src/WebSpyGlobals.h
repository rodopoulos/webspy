/*
 * WebSpyGlobals.h
 *
 *  Created on: 14/04/2015
 *      Author: root
 */

#ifndef WEBSPYGLOBALS_H_
#define WEBSPYGLOBALS_H_

#include <libnet.h>

#include "Host.h"

class WebSpyGlobals {
public:
	static bool  		verbose;
	static bool  		logging;
	static char* 		browser;
	static char* 		iface;
	static char 		libnetErrBuffer[LIBNET_ERRBUF_SIZE];
	static libnet_t* 	context;
	static Host			attacker;
};

#endif /* WEBSPYGLOBALS_H_ */
