/*
 * Globals.cpp
 *
 *  Created on: 10 de ago de 2015
 *      Author: rodopoulos
 */

#include "Globals.h"

using namespace Tins;

Host Globals::attacker;
Host Globals::gateway;
Host Globals::victim;
NetworkInterface Globals::iface;
std::string Globals::ifaceRef;
bool Globals::logging 	= false;
bool Globals::verbose   = false;
bool Globals::automatic = false;


Globals::Globals() {}
Globals::~Globals() {}

void Globals::init(){
	if(automatic == true){
			iface = NetworkInterface::default_interface();
	} else if(ifaceRef.empty()){
		std::cout << "Select a interface:" << std::endl;
		std::vector<NetworkInterface> ifaces = NetworkInterface::all();
		std::vector<NetworkInterface>::iterator it;

		for(it = ifaces.begin(); it != ifaces.end(); it++)
			std::cout << (*it).id() << " - " << (*it).name() << std::endl;
		std::cout << std::setw(4) << std::endl << "Option: ";

		int op;
		std::cin >> op;
		iface = ifaces[op];
	} else {
		NetworkInterface* newIface = new NetworkInterface(ifaceRef);
		iface = *newIface;
	}

	// Setting attacker
	attacker.setName("Attacker");
	attacker.setIP(iface.info().ip_addr);
	attacker.setMAC(iface.info().hw_addr);
	attacker.toString();

	IPv4Address gatewayIp;
	if(!Utils::gateway_from_ip(iface.info().ip_addr, gatewayIp)){
		std::cerr << "\033[1;31m [Error]"
					 " Globals::init ->"
					 "\033[0m gateway not avaiable" << std::endl;
		exit(EXIT_FAILURE);
	}

	PacketSender resolver(iface);
	HWAddress<6> gatewayMac = Utils::resolve_hwaddr(gatewayIp, resolver);

	gateway.setName("Gateway");
	gateway.setIP(gatewayIp);
	gateway.setMAC(gatewayMac);
	gateway.toString();

}

void Globals::setInterface(std::string str){
	ifaceRef = str;
}

