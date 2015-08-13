/*
 * Server.cpp
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#include "Server.h"

Server::Server(int port) {
	server = mg_create_server(NULL, handle)
}

Server::~Server() {
	// TODO Auto-generated destructor stub
}



/************************************************************************
 * * * * * * * * CALLBACKS * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
int Server::handle(struct mg_connection *conn, enum mg_event ev){
	switch(ev){
	case MG_REQUEST: break;
	}
	return MG_FALSE; break;
}
