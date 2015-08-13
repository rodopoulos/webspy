/*
 * Server.h
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SERVER_H_
#define SERVER_H_

#include <vector>
#include "HTTP.h"
#include "mongoose.h"

class Server {
	struct mg_server* server;

	static int handle(struct mg_connection *conn, enum mg_event ev);

public:
	Server(int port = 6080);
	virtual ~Server();

	void loop();
};

#endif /* SERVER_H_ */
