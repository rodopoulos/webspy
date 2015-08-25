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
#include "http/HTTP.h"

class Pipe {
#define MIN_MTU			1514

// Packet analyser commands
#define JUST_RELAY		0
#define STRIP			1
#define	RESET_COOKIE	2
#define RESET_CACHE		3
#define SSL_REQ			4

	static void* connect(void*);
	static bool tcpFollower(Tins::TCPStream& stream);
	static bool httpRecover(Tins::TCPStream& stream);
	void packetAnalyser(Tins::PDU& pdu);
	static void printPacket(Tins::PDU& packet);

public:
	static int count;
	static Tins::PacketSender sender;
	static Tins::TCPStreamFollower assembler;

	Pipe();
	virtual ~Pipe();

	void init();
	static bool relay(Tins::PDU& packet);
};

class GambiarraFilha : public Tins::Gambiarra{
	void callback(Tins::PDU& pdu);
};

#endif /* SRC_PIPE_H_ */
