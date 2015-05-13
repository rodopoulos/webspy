/*
 * main.cpp
 *
 *  Created on: Apr 6, 2015
 *      Author: Felipe Rodopoulos
 */

// std-cpp
#include <iostream>
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
#include "WebSpyGlobals.h"
#include "IPAddress.h"
#include "Host.h"

using namespace std;

static void showUsage(int exitCode){
	cerr << "Usage: webspy [-v] [-l] INTERFACE BROWSER\n"
		 << "Options:\n"
	     << "\t-h,--help\t\tShow this help message\n"
	     << "\t-v,--verbose\t\tEnable verbose mode\n"
	     << "\t-l,--logging\t\tEnable logging (avaiable at ./etc)\n"
	     << endl;
	exit(exitCode);
}

static void parseProgramArguments(int argc, char* argv[]){

	if(argc < 0){
		showUsage(EXIT_FAILURE);
	}

	for(int i = 1; i < argc; i++){
		std::string arg = argv[i];
		if(arg == "-h" || arg == "--help"){
			showUsage(EXIT_SUCCESS);
		} else if(arg == "-l" || arg == "--logging"){
			WebSpyGlobals::logging = true;
		} else if(arg == "-v" || arg == "--verbose"){
			WebSpyGlobals::verbose = true;
		} else if(arg == "chrome" || arg == "mozilla" || arg == "safari"){
			WebSpyGlobals::browser = argv[i];
		} else if(arg == "lan" || arg == "wlan"){
			WebSpyGlobals::iface = argv[i];
		}
	}

	if(!WebSpyGlobals::browser){
		cout << "No browser selected\n";
		showUsage(EXIT_FAILURE);
	}
}

/*
static void selectVictim(vector<Host>& avaiableHosts){
	// TODO
}
*/

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

	WebSpyGlobals::iface = ifacesNames[opt - 1];
}

int main(int argc, char* argv[]){
	//parseProgramArguments(argc, argv);

	if(WebSpyGlobals::iface == NULL){
		selectInterface();
	}

	WebSpyGlobals::context = libnet_init(LIBNET_LINK_ADV, WebSpyGlobals::iface, WebSpyGlobals::libnetErrBuffer);

	if(!WebSpyGlobals::context){
		fprintf(stderr, "webspy: [ERRO] LibNet Error: %s", WebSpyGlobals::libnetErrBuffer);
		exit(EXIT_FAILURE);
	}

	printf("Inteface selected: %s\n", WebSpyGlobals::iface);
	printf("Link type: %d\n", WebSpyGlobals::context->link_type);

	WebSpyGlobals::attacker(libnet_get_ipaddr4(WebSpyGlobals::context),
				  libnet_get_hwaddr(WebSpyGlobals::context),
				  "Attacker");
	printf("You machine trace:\n");
	WebSpyGlobals::attacker.toString();

	//Sweeper sweeper;
	//vector<Host> avaiableHosts = sweeper.sweep();
	// Host& victim = selectVictim(avaiableHosts);

	/*
	// TODO pegar IP e MAC do Gateway
	Host gateway = Host::findGateway(iface);

	Spoofer spoofer(gateway, victim);

	Pipe gateway2victim(gateway, victim);
	Pipe victim2gateway(victim, gateway);

	while(true){
		Renderer renderer();
	}
	*/

	return 0;
}