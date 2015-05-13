/*
 * MACAddress.h
 *
 *  Created on: May 8, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef MACADDRESS_H_
#define MACADDRESS_H_

#include <cstdint>
#include <string>
#include <libnet.h>

#include "WebSpyGlobals.h"

class MACAddress {
	libnet_ether_addr *mac;

public:
	MACAddress();
	MACAddress(std::string mac);
	MACAddress(libnet_ether_addr* mac);
	virtual ~MACAddress();

	void setMACAddress(libnet_ether_addr* mac);
	libnet_ether_addr* getMACAddress();

	std::string toString();
};

#endif /* MACADDRESS_H_ */
