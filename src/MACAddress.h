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

class MACAddress {
	uint64_t mac;

public:
	MACAddress();
	MACAddress(std::string mac);
	MACAddress(uint64_t mac);
	virtual ~MACAddress();

	uint64_t getMACAddress();
	void setMACAddress(std::string mac);
	void setMACAddress(uint64_t mac);

	std::string toString();
};

#endif /* MACADDRESS_H_ */
