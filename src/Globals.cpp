/*
 * Globals.cpp
 *
 *  Created on: 14/04/2015
 *      Author: root
 */

// this
#include "Globals.h"

bool 		Globals::verbose 	= false;
bool 		Globals::logging 	= false;
char* 		Globals::browser 	= NULL;
char* 		Globals::iface 		= NULL;

Host 		Globals::attacker;
Host 		Globals::victim;
Host 		Globals::gateway;

int Globals::readNLMsg(int sock, char* buf, int seqNum, int pid){
	struct nlmsghdr* nlHdr;
	int readLen = 0, msgLen = 0;

	do{
		if((readLen = recv(sock, buf, 4096 - msgLen, 0)) < 0){
			fprintf(stderr, "WebSpy::Globals::readFromSocket > [WARN] Can't read socket.\n");
			// return -1;
		}
		nlHdr = (struct nlmsghdr*) buf;

		if(NLMSG_OK(nlHdr, readLen) == 0 || nlHdr->nlmsg_type == NLMSG_ERROR){
			fprintf(stderr, "WebSpy::Globals::readFromSocket > [WARN] Socket message error:\n");
			if(nlHdr->nlmsg_type == NLMSG_ERROR)
				fprintf(stderr, "\t->message returned is an error message\n");
			else if(NLMSG_OK(nlHdr, readLen) == 0){
				fprintf(stderr, "\t->Message returned doesn't have expected length\n");
				fprintf(stderr, "\t->Message size:  %u\n", nlHdr->nlmsg_len);
				fprintf(stderr, "\t->Expected size: %u\n", (int)sizeof(nlmsghdr));
			}
			exit(EXIT_FAILURE);
			// return -1;
		}

		if (nlHdr->nlmsg_type == NLMSG_DONE)
			break;
		else {
			buf += readLen;
			msgLen += readLen;
		}

		/* Check if its a multi part message */
		if ((nlHdr->nlmsg_flags & NLM_F_MULTI) == 0)
			break;

	} while((nlHdr->nlmsg_seq != (unsigned)seqNum) || (nlHdr->nlmsg_pid != (unsigned)pid));
	return msgLen;
}

uint32_t Globals::getGatewayByNLMsg(){
	int sock, len, msgSeq = 0;
	struct timeval tv;

	// Instanciando o socket
	if((sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) < 0){
		fprintf(stderr, "WebSpy::Globals::findGatewayByNLMsg > [WARN] Can't open socket\n");
		return GW_ERROR;
	}

	// Criando mensagem do tipo RT_REQUEST onde são solicitadas as rotas das interfaces
	char msgBuf[NL_BUF_SIZE];
	memset(msgBuf, 0, NL_BUF_SIZE);
	struct nlmsghdr *nlMsg;
	nlMsg = (struct nlmsghdr*) msgBuf;
	nlMsg->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
	nlMsg->nlmsg_type  = RTM_GETROUTE;
	nlMsg->nlmsg_flags = NLM_F_DUMP | NLM_F_REQUEST;
	nlMsg->nlmsg_seq   = msgSeq++;
	nlMsg->nlmsg_pid   = getpid();

	// Sending the message through the socket
	tv.tv_sec = 1;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *)&tv, sizeof(struct timeval));
	if(send(sock, nlMsg, nlMsg->nlmsg_len, 0) < 0){
		fprintf(stderr, "WebSpy::Globals::findGateway > [WARN] Can't use socket.\n");
		return GW_ERROR;
	}

	// Listening from the socket
	if((len = readNLMsg(sock, msgBuf, msgSeq, getpid())) < 0){
		fprintf(stderr, "WebSpy::Globals::findGateway > [WARN] Can't read from socket.\n");
		return GW_ERROR;
	}


	struct rtmsg*  rtMsg;
	struct rtattr* rtAttr;
	for (; NLMSG_OK(nlMsg, len); nlMsg = NLMSG_NEXT(nlMsg, len)) {
		rtMsg = (struct rtmsg *) NLMSG_DATA(nlMsg);

		if(rtMsg->rtm_family != AF_INET || rtMsg->rtm_table != RT_TABLE_MAIN)
			continue;

		rtAttr = (struct rtattr*) RTM_RTA(rtMsg);
		int rtAttrLen = RTM_PAYLOAD(nlMsg);

		for(; RTA_OK(rtAttr, rtAttrLen); RTA_NEXT(rtAttr, rtAttrLen)){
			printf("Estou olhando para %d \n", rtAttr->rta_type);
			if(rtAttr->rta_type == RTA_GATEWAY){
				printf("\tACHEI\n");
				close(sock);
				return (uint32_t) (*(u_int *) RTA_DATA(rtAttr));
			} else{
				continue;
			}
		}
	}

	close(sock);
	return GW_ERROR;
}

uint32_t Globals::getGatewayByNetstat(){
	char gateway[16];
	char cmd [1000] = {0x0};

	printf("\n\nTENTANDO POR NETSTAT\n");

	sprintf(cmd,"route -n | grep %s  | grep 'UG[ \t]' | awk '{print $2}'", iface);
	FILE* fp = popen(cmd, "r");
	char line[256]={0x0};

	if(fgets(line, sizeof(line), fp) != NULL){
		strcpy(gateway, line);
		gateway[strlen(gateway) -1 ] = '\0';
	}else{
		pclose(fp);
		return GW_ERROR;
	}

	pclose(fp);
	uint32_t ip;
	inet_pton(AF_INET, gateway, &ip);
	return ip;

}

void Globals::findGateway(){
	uint32_t ip = getGatewayByNLMsg();
	if(ip == GW_ERROR){
		printf("\nNEM ROLOU ip: %d\n", ip);
		ip = getGatewayByNetstat();
		if(ip == GW_ERROR){
			return;
		}
	}

	// Se nada der errado, atribui o IP
	gateway.setIP(ip);
	gateway.setName("Gateway");
}

void Globals::findAttacker(){
	libnet_t* context;
	char errBuf[LIBNET_ERRBUF_SIZE];

	if((context = libnet_init(LIBNET_LINK_ADV, iface, errBuf)) == NULL){
		fprintf(stderr,
				"WebSpy::Globals::findAttacker > "
				"[ERROR] can't init Libnet: %s\n",
				libnet_geterror(context)
		);
		exit(EXIT_FAILURE);
	}
	attacker.setIP(libnet_get_ipaddr4(context));
	attacker.setMAC(libnet_get_hwaddr(context));
	attacker.setName("Attacker (you)");
	libnet_destroy(context);
}
