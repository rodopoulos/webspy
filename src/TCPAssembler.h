/*
 * TCPAssembler.h
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SRC_TCPASSEMBLER_H_
#define SRC_TCPASSEMBLER_H_

#include <nids.h>
#include <cstdlib>

class TCPAssembler {

	static void* segmentHandle(struct tcp_stream *conn, void ** invalid);

public:
	TCPAssembler();
	virtual ~TCPAssembler();

	void config(pcap_t* pcap);
	void start();
	void assembly(struct pcap_pkthdr* header, const unsigned char* rcvdPacket);
};

#endif /* SRC_TCPASSEMBLER_H_ */
