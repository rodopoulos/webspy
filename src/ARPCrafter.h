/*
 * ARPCrafter.h
 *
 *  Created on: 13/05/2015
 *      Author: rodopoulos
 */

#ifndef SRC_ARPCRAFTER_H_
#define SRC_ARPCRAFTER_H_

#include <libnet.h>

class ARPCrafter {

private:
	libnet_t* context;
	libnet_ptag_t header;

	static uint8_t 			zeroedMac[6];
	static uint8_t 			broadcastMac[6];

	void refreshContext();
public:
	uint16_t op;
	uint32_t senderIP;
	uint32_t targetIP;
	libnet_ether_addr* senderMAC;
	libnet_ether_addr* targetMAC;

	ARPCrafter();
	ARPCrafter(libnet_t* context);
	virtual ~ARPCrafter();

	libnet_ptag_t newArp(uint16_t operation,
						 libnet_ether_addr* senderMAC,
						 uint32_t senderIP,
						 libnet_ether_addr* targerMAC,
						 uint32_t targetIP);

	void setSenderMAC(libnet_ether_addr* mac);
	void setTargetMAC(libnet_ether_addr* mac);
	void setBroadcastMAC();
	void setSenderIP(uint32_t ip);
	void setTargetIP(uint32_t ip);
	void setARPOperation(uint16_t op);
};

#endif /* SRC_ARPCRAFTER_H_ */
