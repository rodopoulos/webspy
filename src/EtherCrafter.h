/*
 * EtherCrafter.h
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#ifndef ETHERCRAFTER_H_
#define ETHERCRAFTER_H_

#include <libnet.h>

class EtherCrafter {
private:
	libnet_t* 	  context;
	libnet_ptag_t header;

	void refreshContext();

public:
	static uint8_t 		zeroedMac[6];
	static uint8_t 		broadcastMac[6];
	libnet_ether_addr* 	senderMAC;
	libnet_ether_addr* 	targetMAC;
	uint16_t		   	upperProtocol;

	EtherCrafter();
	EtherCrafter(libnet_t* context);
	virtual ~EtherCrafter();
	libnet_ptag_t newEther(libnet_ether_addr* senderMAC ,libnet_ether_addr* targetMAC, uint16_t protocol);
	void setSenderMAC(libnet_ether_addr* mac);
	void setTargetMAC(libnet_ether_addr* mac);
	void setBroadcasMAC();
	void setUpperProtocol(uint16_t protocol);
};

#endif /* ETHERCRAFTER_H_ */
