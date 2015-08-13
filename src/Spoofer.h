/*
 * Spoofer.h
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SRC_SPOOFER_H_
#define SRC_SPOOFER_H_

#include <pthread.h>
#include <tins/tins.h>
#include "Globals.h"
#include "Host.h"

class Spoofer {
	static Tins::PacketSender sender;
	static Tins::EthernetII toGateway, toVictim;

	static void* spoof(void* args);

public:
	Spoofer();
	virtual ~Spoofer();

	void init();
	static bool arpHandle(Tins::PDU& packet);
};

#endif /* SRC_SPOOFER_H_ */
