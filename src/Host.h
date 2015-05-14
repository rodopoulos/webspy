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
#include <libnet.h>

class Host {
private:
	static int currentID;
public:
	int id;
	uint32_t ip;
	libnet_ether_addr* mac;
	std::string name;

	// Constructors
	Host();
	Host(uint32_t ip, libnet_ether_addr* mac, std::string name);
	virtual ~Host();

	// Getters e Setters
	void setIP(uint32_t ip);
	void setMAC(libnet_ether_addr* mac);
	void setName(std::string name);
	libnet_ether_addr* getMAC();
	uint32_t getIP();
	std::string getName();

	// Utils
	void toString();
	char* macToString(libnet_ether_addr* mac);
	char* ipToString(uint32_t ip);

};

#endif /* HOST_H_ */
