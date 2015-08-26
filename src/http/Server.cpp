/*
 * Server.cpp
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#include "Server.h"

namespace HTTP {
std::list<Response*> Server::content;
pthread_mutex_t      Server::contentMutex;
Response*		     Server::currentPage;

Server::Server(){
	server = mg_create_server(NULL, handle);
	mg_set_option(server, "listening_port", "6080");
	mg_set_option(server, "document_root", ".");
	pthread_mutex_init(&contentMutex, nullptr);
}

Server::~Server(){}

/******************************************************************************
 * * * * * * * * PUBLIC * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *****************************************************************************/
void Server::loop(){
	std::cout << "Server inited on port 6080" << std::endl;
	for(;;){
		mg_poll_server(server,1000);
	}
	mg_destroy_server(&server);
}

void Server::addContent(HTTP::Response* newContent){
	if(newContent->hasHeader("Content-Type")){
		std::string type = newContent->getHeader("Content-Type");
		if(type.find("text/html") != std::string::npos
				&& newContent->code == "200"){
			currentPage = newContent;
			pthread_t trigger;
			pthread_create(&trigger, nullptr, initBrowser, nullptr);
		}
	}

	pthread_mutex_lock(&contentMutex);
	content.push_back(newContent);
	pthread_mutex_unlock(&contentMutex);
}

void* Server::initBrowser(void* args){
	sleep(5);
	system("xdg-open http://localhost:6080/");
	return nullptr;
}

/******************************************************************************
 * * * * * * * * CALLBACKS * * * * * * * * * * * * * * * * * * * * * * * * * *
 *****************************************************************************/
int Server::handle(struct mg_connection *conn, enum mg_event ev){
	switch(ev){
	case MG_AUTH: return MG_TRUE; break;
	case MG_REQUEST:
		return serveRequest(conn);
		break;
	default: break;
	}
	return MG_FALSE;
}

/******************************************************************************
 * * * * * * * * SERVER * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *****************************************************************************/
int Server::serveRequest(struct mg_connection *conn){
	Response* object;
	if(!strcmp(conn->uri, "/")){
		object = currentPage;
	} else{
		std::string uri = conn->uri;
		try{
			object = retrieveContent(uri);
		} catch(std::exception &e){
			return MG_FALSE;
		}
	}
	pthread_mutex_lock(&contentMutex);
	for(auto it = object->headers.begin();it != object->headers.end(); it++){
		std::cout << it->first << ": " << it->second << std::endl;
		mg_send_header(conn, it->first.c_str(), it->second.c_str());
	}
	mg_printf_data(conn, object->body, sizeof(object->body));
	pthread_mutex_unlock(&contentMutex);
	delete object;
	return MG_TRUE;
}

Response* Server::retrieveContent(std::string uri){
	for(auto it = content.begin(); it != content.end(); it++){
		if((*it)->uri == uri){
			Response* object = *it;
			content.erase(it);
			return object;
		}
	}
	std::exception e;
	throw e;
}

void Server::assignPage(Response* response){
	pthread_mutex_lock(&contentMutex);
	currentPage = response;
	system("xdg-open http://localhost:6080/");
	pthread_mutex_unlock(&contentMutex);
}

} /* namespace HTTP */
