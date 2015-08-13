/*
 * Pipe.h
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SRC_PIPE_H_
#define SRC_PIPE_H_

#include <pthread.h>
#include <tins/tins.h>
#include "Globals.h"

class Pipe {
#define MTU 1514

	static int count;
	static Tins::PacketSender sender;
	static Tins::TCPStreamFollower assembler;
	//Renderer* renderer

	static void* connect(void*);
	static bool relay(Tins::PDU& packet);
	static bool tcpFollower(Tins::TCPStream& stream);
	static bool httpRecover(Tins::TCPStream& stream);
public:
	Pipe();
	virtual ~Pipe();

	void init();
};

#endif /* SRC_PIPE_H_ */
