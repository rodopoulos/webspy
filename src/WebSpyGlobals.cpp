/*
 * WebSpyGlobals.cpp
 *
 *  Created on: 14/04/2015
 *      Author: root
 */

// this
#include "WebSpyGlobals.h"

bool WebSpyGlobals::verbose = false;
bool WebSpyGlobals::logging = false;
char* WebSpyGlobals::browser = NULL;
char* WebSpyGlobals::iface = NULL;
char WebSpyGlobals::libnetErrBuffer[LIBNET_ERRBUF_SIZE];
libnet_t* WebSpyGlobals::context;
Host WebSpyGlobals::attacker;

