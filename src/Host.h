/*
 * Host.h
 *
 *  Created on: 15/04/2015
 *      Author: root
 */

#ifndef HOST_H_
#define HOST_H_

#include <string>
#include <vector>
#include "IPAddress.h"
#include "MACAddress.h"

class Host {
private:
	static int currentID;
public:
	int id;
	IPAddress ip;
	MACAddress mac;
	std::string name;

	// Constructors
	Host();
	Host(uint32_t ip, uint64_t mac, std::string name);
	virtual ~Host();

	// Getters e Setters
	void setIP(uint32_t ip);
	void setMAC(uint64_t mac);
	void setName(std::string name);

	// Main Methods
	Host& selectVictim(std::vector<Host*>& avaiableHosts);
	void printHostList(std::vector<Host*>& hosts);
	void sortByIP(std::vector<Host*>&);
	void setHost();

	// Utils
	void toString();

};

#endif /* HOST_H_ */
