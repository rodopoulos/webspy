/*
 * Sniffer.h
 *
 *  Created on: 15/05/2015
 *      Author: rodopoulos
 */

#ifndef SNIFFER_H_
#define SNIFFER_H_

#include <pcap.h>
#include <string>

#include "Globals.h"
#include "Host.h"

class Sniffer {

private:
	pcap_t* 			handle;
	int					linkType;
	int					linkHrdLen;
	struct bpf_program 	filter;
	char				errBuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr 	packet;

	char*				filterExpression;

public:
	bpf_u_int32			mask;
	bpf_u_int32			lan;

	/****************************************************
	 * +++++++++++++++++ METHODS ++++++++++++++++++++++++
	 ***************************************************/

	/* ================== Constructors =============== */
	Sniffer();
	Sniffer(char filter[]);
	Sniffer(char filter[], int timeout);
	virtual ~Sniffer();

	/* ================== Listeners ================== */
	const unsigned char* nextPacket();
	void listen(pcap_handler callback);
	void listen(pcap_handler callback, int packets);
	void listenWithTimeout(pcap_handler callback);

	/* ================== Modifiers ================== */
	void init();
	void close();

	/* =================== Setters =================== */
	void setFilter(const char* filter);
	void setTimeout(int time);
	void setDirection(pcap_direction_t direction);

	/* =================== Getters =================== */
	const char* getLinkName();
	void getLANProps();
	void showLANProps();
};

#endif /* SNIFFER_H_ */
