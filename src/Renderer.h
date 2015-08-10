/*
 * Renderer.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef RENDERER_H_
#define RENDERER_H_

#include <cstdio>
#include <queue>
#include <map>
#include <pthread.h>
#include "Crafter.h"
#include "Protocols.h"
#include "HTTPSession.h"
#include "mongoose.h"

class Renderer {
	pthread_t 	bufferThread;
	std::vector<HTTPSession*> sessions;
	struct mg_server *server;

	static void* rendererReceiver(void* args);
	static int 	 srvEventHandler(struct mg_connection *conn, enum mg_event ev);
	static void  answerRequest(struct mg_connection *conn);

public:
	static pthread_mutex_t  rendererMutex;
	static std::queue<HTTP> rendererBuffer;

	Renderer();
	virtual ~Renderer();
	void 		 init();
	void 		 serverLoop();
	void 		 addNewSession(HTTPSession* session);
	bool		 isNewSession(HTTP* request);
	HTTPSession* retrieveSession(HTTP* http, int method);
};

#endif /* RENDERER_H_ */
