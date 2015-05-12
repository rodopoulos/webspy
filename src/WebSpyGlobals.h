/*
 * WebSpyGlobals.h
 *
 *  Created on: 14/04/2015
 *      Author: root
 */

#ifndef WEBSPYGLOBALS_H_
#define WEBSPYGLOBALS_H_

#include <string>

class WebSpyGlobals {
public:
	static bool verbose;
	static bool logging;
	static std::string browser;
	static std::string interface;
	static std::string myIP;
	static std::string myMAC;
};

#endif /* WEBSPYGLOBALS_H_ */
