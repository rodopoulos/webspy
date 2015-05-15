/*
 * Sweeper.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef SWEEPER_H_
#define SWEEPER_H_

#include <string>
#include <vector>
#include <cmath>
#include <libnet.h>
#include <pcap.h>

#include "Host.h"
#include "Sniffer.h"
#include "ARPCrafter.h"
#include "EtherCrafter.h"

class Sweeper {
private:
	static libnet_ptag_t	etherHeader;

	void configARPSniffer();
	void testHeader(libnet_ptag_t header);

public:
	Sweeper();
	virtual ~Sweeper();

	std::vector<Host> sweep();
};

#endif /* SWEEPER_H_ */
