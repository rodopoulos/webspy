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
	static Response* currentPage;
	static std::list<Response*> content;
	static pthread_mutex_t contentMutex;
	struct mg_server* server;

	static int   handle(struct mg_connection *conn, enum mg_event ev);
	static int	 serveRequest(struct mg_connection *conn);
	static void*  initBrowser(void* args);
	static HTTP::Response* retrieveContent(std::string uri);

public:
	Server();
	virtual ~Server();

	void loop();
	void addContent(HTTP::Response* newContent);
	static void assignPage(Response* response);
};

} /* namespace HTTP */

#endif /* SERVER_H_ */
