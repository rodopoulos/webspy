/*
 * ARPCrafter.h
 *
 *  Created on: 13/05/2015
 *      Author: rodopoulos
 */

#ifndef SRC_ARPCRAFTER_H_
#define SRC_ARPCRAFTER_H_

#include <libnet.h>

struct ARPPacket{
	uint16_t	htype;
	uint16_t	ptype;
	uint8_t		hsize;
	uint8_t		psize;
	uint16_t	arpOp;
	uint8_t		shaddr[6];
	uint32_t	spaddr;
	uint8_t		thaddr[6];
	uint32_t	tpaddr;
	ARPPacket(unsigned char* buf);
};

class ARPCrafter {

private:
	libnet_t* 		context;
	libnet_ptag_t 	header;

	void refreshContext();
public:

	uint16_t 			op;
	uint32_t 			senderIP;
	uint32_t 			targetIP;
	libnet_ether_addr* 	senderMAC;
	libnet_ether_addr* 	targetMAC;
	static uint8_t 		zeroedMac[6];
	static uint8_t 		broadcastMac[6];

	ARPCrafter();
	ARPCrafter(libnet_t* context);
	virtual ~ARPCrafter();

	libnet_ptag_t newARP(uint16_t operation,
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

	static const char* getARPOperationName(int op);
};

#endif /* SRC_ARPCRAFTER_H_ */
