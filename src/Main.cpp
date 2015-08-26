/*
 * main.cpp
 *
 *  Created on: Apr 6, 2015
 *      Author: Felipe Rodopoulos
 */

//std-c
#include <stdio.h>

//wepspy
#include "Globals.h"
#include "Sweeper.h"
#include "Host.h"
#include "Spoofer.h"
#include "Pipe.h"

using namespace std;
using namespace HTTP;

static void showUsage(int exitCode){
	fprintf(stderr, "Usage: webspy [-v] [-l] [-i iface] [-V victim]\n");
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h,--help          Show this help message\n");
	fprintf(stderr, "    -v,--verbose       Enable verbose mode\n");
	fprintf(stderr, "    -a,--automatic     Program will get default interface\n");
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
		} else if(arg == "-a" || arg == "--automatic"){
			Globals::automatic = true;
		} else if(arg == "-i" || arg == "--iface"){
			std::string iface = argv[i+1];
			Globals::setInterface(iface);
			i++;
		} else if(arg == "-V" || arg == "--victim"){
			Tins::IPv4Address ip(argv[i+1]);
			Globals::victim.setIP(ip);
			i++;
		} else{
			printf("Unrecognized argument: %s\n", argv[i]);
			showUsage(EXIT_FAILURE);
		}
	}
}

int main(int argc, char* argv[]){
	parseProgramArguments(argc, argv);
	Globals::init();

	if(!Globals::victim.ip){
		Sweeper sweeper;
		sweeper.sweep();
		Globals::victim = sweeper.selectHost();
	} else {
		Tins::PacketSender resolver(Globals::iface);
		Globals::victim.setMAC(Tins::Utils::resolve_hwaddr(Globals::victim.ip, resolver));
	}
	Globals::victim.setName("Victim");
	Globals::victim.toString();

	Spoofer spoofer;
	spoofer.init();

	Pipe pipe;
	Server server;

	pipe.setServer(&server);
	pipe.init();

	server.loop();

	return 0;
}
