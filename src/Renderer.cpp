/*
 * Renderer.cpp
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#include "Renderer.h"

std::queue<HTTP> Renderer::rendererBuffer;
pthread_mutex_t  Renderer::rendererMutex;

/************************************************************************
 * * * * * * * * CONSTRUCTORS * * * * * * * * * * * * * * * * * * * * * *
 ************************************************************************/
Renderer::Renderer(){
	server = mg_create_server(NULL, srvEventHandler);
	mg_set_option(server, "document_root", "../www");
	mg_set_option(server, "listening_port", "8080");
}

Renderer::~Renderer() {
	// TODO Auto-generated destructor stub
}






/************************************************************************
 * * * * * * * * * * PUBLIC ACTIONS * * * * * * * * * * * * * * * * * * *
 ************************************************************************/
void Renderer::init(){
	// Initing HTTP buffer thread
	if(pthread_mutex_init(&rendererMutex, NULL) < 0){
		printf("Webspy::Renderer::init > [ERRO] can't init renderer mutex\n");
		exit(EXIT_FAILURE);
	}
}

void Renderer::serverLoop(){
	// Initing server loop
	printf("Local rendering server avaiable on localhost:8080\n");
	for(;;){
		mg_poll_server(server, 1000);
	}

	mg_destroy_server(&server);
}





/************************************************************************
 * * * * * * * * CALLBACKS * * * * * * * * * * * * * * * * * * * * * * **
 ************************************************************************/
void* Renderer::rendererReceiver(void* args){
	return nullptr;
}

int Renderer::srvEventHandler(struct mg_connection *conn, enum mg_event ev){
	switch (ev){
		case MG_REQUEST:
			if(!rendererBuffer.empty()){
				answerRequest(conn);
			} else {
				mg_printf_data(conn, "No screen to render");
			}
			return MG_TRUE;
		break;
		default: return MG_FALSE; break;
	}
}





/************************************************************************
 * * * * * * * * SERVER ACTIONS * * * * * * * * * * * * * * * * * * * * *
 ************************************************************************/

void Renderer::answerRequest(struct mg_connection *conn){
	pthread_mutex_lock(&rendererMutex);
	do{
		HTTP http = rendererBuffer.front();
		rendererBuffer.pop();
		printf("%s\n", http.data);
	} while(!rendererBuffer.empty());
	pthread_mutex_unlock(&rendererMutex);

	//mg_printf_data(conn, http.data);

}
