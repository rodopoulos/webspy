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
#include "http/Server.h"

class Pipe {
#define MIN_MTU			1514
	static HTTP::Server *server;

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
	static void setServer(HTTP::Server *server);
	static bool relay(Tins::PDU& packet);
};

class GambiarraFilha : public Tins::Gambiarra{
	void callback(Tins::PDU& pdu);
};

#endif /* SRC_PIPE_H_ */
