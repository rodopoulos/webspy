/*
 * Host.h
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SRC_HOST_H_
#define SRC_HOST_H_

#include <iostream>
#include <tins/tins.h>

class Host {
public:
	Tins::IPv4Address  ip;
	Tins::HWAddress<6> mac;
	std::string 	   name;

	Host();
	Host(Tins::IPv4Address ip, Tins::HWAddress<6> mac);
	virtual ~Host();

	void setName(std::string name);
	void setIP(Tins::IPv4Address ip);
	void setMAC(Tins::HWAddress<6> mac);
	bool isDefined();
	void toString(int id = 0);

};

#endif /* SRC_HOST_H_ */
