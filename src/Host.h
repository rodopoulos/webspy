/*
 * Host.h
 *
 *  Created on: 15/04/2015
 *      Author: Felipe Rodopoulos
 */

#ifndef HOST_H_
#define HOST_H_

#include <cstdio>
#include <string>
#include <vector>
#include <libnet.h>

class Host {
public:
	int id;
	uint32_t ip;
	libnet_ether_addr* mac;
	std::string name;

	// Constructors
	Host();
	Host(uint32_t ip, libnet_ether_addr* mac, std::string name);
	Host(uint32_t ip, uint8_t* mac, std::string name);
	virtual ~Host();

	// Getters e Setters
	void setIP(uint32_t ip);
	void setIP(std::string ip);
	void setMAC(libnet_ether_addr* mac);
	void setMAC(uint8_t mac[]);
	void setName(std::string name);
	libnet_ether_addr* getMAC();
	uint32_t getIP();
	std::string getName();

	// Utils
	void toString();
	static char* getMACVendor(uint8_t mac[]);
	static std::string macToString(libnet_ether_addr* mac);
	static std::string macToString(uint8_t mac[]);
	static std::string ipToString(uint32_t ip);
	static bool isSameMAC(uint8_t mac1[], uint8_t mac2[]);
	static bool isDefined(Host host);
	static bool isDefined(Host* host);
};

#endif /* HOST_H_ */
