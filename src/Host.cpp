/*
 * Host.cpp
 *
 *  Created on: 15/04/2015
 *      Author: root
 */

// this
#include "Host.h"

// std
#include <iostream>

using namespace std;

int Host::currentID = 0;

// Constructors ------------------------------------------------------------------------

Host::Host() {
	this->id = currentID;
	currentID++;
}

Host::Host(uint32_t ip, uint64_t mac, string name) : ip(ip), mac(mac), name(name){
	this->id = currentID;
	currentID++;
}

Host::~Host() {}

// Main Methods ------------------------------------------------------------------------

Host& Host::selectVictim(vector<Host*>& avaiableHosts){
	sortByIP(avaiableHosts);
	printHostList(avaiableHosts);

	int victimID;
	cout << endl << "Select desired victim (ID, IP or MAC): " << endl;
	cin >> victimID;

	return *avaiableHosts[victimID];
}

void Host::sortByIP(vector<Host*>& hostList){

}

void Host::printHostList(vector<Host*>& hostList){
	vector<Host*>::iterator it;
	int count = 1;
	for(it = hostList.begin(); it != hostList.end(); it++){
		//cout << count << ". Host with IP " << it->IP << " and MAC " << it->MAC << endl;
		count++;
	}
}

// Getters e Setters --------------------------------------------------------------------

void setIP(string IP){

}

void setMAC(string MAC){

}

void setName(string name){

}

// Utils --------------------------------------------------------------------------------

void Host::toString(){
	cout << "Host " << this->id
		 << " -> IP: " << this->ip
		 << " MAC: " << this->mac
		 << " with name " << this->name << "\n";
}

