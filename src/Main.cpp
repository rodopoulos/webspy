/*
 * main.cpp
 *
 *  Created on: Apr 6, 2015
 *      Author: Felipe Rodopoulos
 */

// std
#include <iostream>

//local
#include "WebSpyGlobals.h"
#include "IPAddress.h"

using namespace std;

static void showUsage(){
	cerr << "Usage: webspy [-v] [-l] INTERFACE BROWSER\n"
		 << "Options:\n"
	     << "\t-h,--help\t\tShow this help message\n"
	     << "\t-v,--verbose\t\tEnable verbose mode\n"
	     << "\t-l,--logging\t\tEnable logging (avaiable at ./etc)\n"
	     << endl;
}

static void parseProgramArguments(int argc,char* argv[]){
	for(int i = 1; i < argc; i++){
		std::string arg = argv[i];
		if(arg == "-h" || arg == "--help"){
			showUsage();
		} else if(arg == "-l" || arg == "--logging"){
			WebSpyGlobals::logging = true;
		} else if(arg == "-v" || arg == "--verbose"){
			WebSpyGlobals::verbose = true;
		} else if(arg == "chrome" || arg == "mozilla" || arg == "safari"){
			WebSpyGlobals::browser = argv[i];
		} else if(arg == "lan" || arg == "wlan"){
			//WebSpyGlobals::interface = argv[i];
			//WebSpyGlobals::interface = "wlp2s0";
			WebSpyGlobals::interface = "enp4s0";
		}
	}

	if(WebSpyGlobals::interface.empty()){
		cout << "No interface selected\n";
		showUsage();
	}
	if(WebSpyGlobals::browser.empty()){
		cout << "No browser selected\n";
		showUsage();
	}
}

static void selectVictim(vector<Host>& avaiableHosts){
	// TODO
}

int main(int argc, char* argv[]){

	if(argc < 0){
		showUsage();
		return 1;
	}
	parseProgramArguments(argc, argv);

	Sweeper sweeper;
	vector<Host> avaiableHosts = sweeper.sweep();
	Host& victim = selectVictim(avaiableHosts);

	// TODO pegar IP e MAC do Gateway
	Host gateway = Host::findGateway(iface);

	Spoofer spoofer(gateway, victim);

	Pipe gateway2victim(gateway, victim);
	Pipe victim2gateway(victim, gateway);

	while(true){
		Renderer renderer();
	}

	return 0;
}
