/*
 * Globals.h
 *
 *  Created on: 14/04/2015
 *      Author: root
 */

#ifndef GLOBALS_H_
#define GLOBALS_H_

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <libnet.h>

#include "Host.h"

#define NL_BUF_SIZE 4096
#define GW_ERROR 	  (unsigned)-1

class Globals {
	static int readNLMsg(int sock, char *buf, int seqNum, int pid);
	static uint32_t getGatewayByNetstat();
	static uint32_t getGatewayByNLMsg();
public:
	static bool  	verbose;
	static bool  	logging;
	static char* 	browser;
	static char* 	iface;

	static Host		attacker;
	static Host		victim;
	static Host		gateway;

	static void findGateway();
	static void	findAttacker();
};

#endif /* GLOBALS_H_ */
