/*
 * TCPAssembler.cpp
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#include "TCPAssembler.h"

TCPAssembler::TCPAssembler() {}
TCPAssembler::~TCPAssembler() {}





void TCPAssembler::config(pcap_t* pcap){
	printf("TCP Assembler: config made!\n");
	nids_params.pcap_desc = pcap;
	if(!nids_init()){
		fprintf(stderr, "Webspy::TCPAssembler::config > [ERRO] can't init assembler\n");
		exit(1);
	}
	nids_register_tcp((void*)segmentHandle);
}

void TCPAssembler::start(){
	printf("TCP Assembler started!\n");
	nids_run();
}

void TCPAssembler::assembly(struct pcap_pkthdr* header, const unsigned char* rcvdPacket){
	nids_pcap_handler(nullptr, header, (u_char*)rcvdPacket);
}





void* TCPAssembler::segmentHandle(struct tcp_stream *conn, void ** invalid){
	printf("Some tcp is here!\n");
	if(conn->nids_state == NIDS_JUST_EST){
		conn->client.collect++;
		conn->server.collect++;
		printf("Conexão iniciada!\n");
	} else if(conn->nids_state == NIDS_DATA){
		printf("[ DADOS ]");
		if(conn->client.count_new){
			printf(" Vitima \n");
		} else {
			printf(" Ataque \n");
		}
	} else if(conn->nids_state == NIDS_CLOSE){
		printf("Conexão fechada!\n");
	}
	return nullptr;
}
