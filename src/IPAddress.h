/*
 * IPAddress.h
 *
 *  Created on: May 5, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef IPADDRESS_H_
#define IPADDRESS_H_

#include <cstdint>
#include <string>

class IPAddress {
	uint32_t ip;
public:
	IPAddress();
	IPAddress(std::string ip);
	IPAddress(uint32_t ip);
	virtual ~IPAddress();

	uint32_t getIPAddress();
	void setIPAddress(std::string ip);
	void setIPAddress(uint32_t ip);

	IPAddress operator + (uint32_t);
	IPAddress operator ++ ();
	std::string toString();
};

#endif /* IPADDRESS_H_ */
