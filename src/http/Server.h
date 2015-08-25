/*
 * Server.h
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SERVER_H_
#define SERVER_H_

#include <list>
#include <string>
#include <unistd.h>

#include "HTTP.h"
#include "Session.h"
#include "mongoose.h"

namespace HTTP {

class Server {
	static std::list<Session> sessions;
	static pthread_mutex_t sessionMutex;
	struct mg_server* server;
	int port;

	static int   handle(struct mg_connection *conn, enum mg_event ev);
	static int	 serveRequest(struct mg_connection *conn);
	static int   getSessionID(struct mg_connection *conn);
	static void* sessionChecker(void* args);
	static void  triggerBrowser(long int id);

public:
	Server();
	virtual ~Server();

	void loop();

	static void		addSession(Session session);
	static void 	addContentToSession(std::string host, Response content);
	static bool	 	hasSession(std::string host);
};

} /* namespace HTTP */

#endif /* SERVER_H_ */
