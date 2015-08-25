/*
 * Server.cpp
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#include "Server.h"

namespace HTTP {

std::list<Session> Server::sessions;
pthread_mutex_t    Server::sessionMutex;

Server::Server(){
	server = mg_create_server(NULL, handle);
	mg_set_option(server, "listening_port", "6080");
	mg_set_option(server, "document_root", ".");
	pthread_mutex_init(&sessionMutex, nullptr);
}

Server::~Server(){}

void* Server::sessionChecker(void* args){
	while(1==1){
		pthread_mutex_lock(&sessionMutex);
		if(!sessions.empty()){
			for(auto it = sessions.begin(); it != sessions.end(); it++){
				if((*it).status == Session::READY){
					(*it).status = Session::DONE;
					triggerBrowser((*it).id);
				} else continue;
			}
		}
		pthread_mutex_unlock(&sessionMutex);
	}
}

void Server::triggerBrowser(long int id){
	std::stringstream stream;
	stream << "xdg-open http://localhost:6080/" << id;
	sleep(2);
	system(stream.str().c_str());
}

void Server::loop(){
	std::cout << "Server inited on port 6080" << std::endl;
	pthread_t checkerThread;
	pthread_create(&checkerThread, nullptr, sessionChecker, nullptr);
	for(;;){
		mg_poll_server(server,1000);
	}
	mg_destroy_server(&server);
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

int Server::getSessionID(struct mg_connection *conn){
	const char* tmp = mg_get_header(conn, "Referer");
	char* id;
	if(tmp) // eh um objeto da pagina
		id = (char*) tmp;
	else  // eh a propria pagina
		id = (char*) conn->uri;
	id = strrchr(id, '/') + 1;
	return atoi(id);
}

int Server::serveRequest(struct mg_connection *conn){
	Session *session = nullptr;
	std::cout << conn->content << std::endl << std::endl;
	if(!sessions.empty()){
		int sessionID = getSessionID(conn);
		pthread_mutex_lock(&sessionMutex);
		for(auto it = sessions.begin(); it != sessions.end(); it++){
			if((*it).id == sessionID){
				session = &(*it);
				break;
			} else continue;
		}
		pthread_mutex_unlock(&sessionMutex);

		if(session != nullptr){
			std::string uri = conn->uri;
			if(!mg_get_header(conn, "Referer"))
				uri = session->path;
			try{
				Response response = session->popRequestedElement(uri);
				for(auto it = response.headers.begin();it != response.headers.end();it++){
					mg_send_header(conn, it->first.c_str(), it->second.c_str());
				}
				mg_printf_data(conn, response.body, sizeof(response.body));
				return MG_TRUE;
			} catch(std::exception& e){
				std::cout << "\033[1;33m[WARNING]\033[0m No object\033[0;1m "
						  << uri << "\033[0m found." << std::endl;
			}
		}
	}
	return MG_FALSE;
}




/******************************************************************************
 * * * * * * * * * * SESSIONS * * * * * * * * * * * * * * * * * * * * * * * * *
 *****************************************************************************/
void Server::addSession(Session session){
	pthread_mutex_lock(&sessionMutex);
	sessions.push_back(session);
	pthread_mutex_unlock(&sessionMutex);
}

void Server::addContentToSession(std::string host, Response content){
	auto it = sessions.begin();
	pthread_mutex_lock(&sessionMutex);
	for(; it != sessions.end(); it++){
		if((*it).host == host)
			(*it).addContent(content);
		break;
	}
	pthread_mutex_unlock(&sessionMutex);
}

bool Server::hasSession(std::string host){
	auto it = sessions.begin();
	for(; it != sessions.end(); it++){
		if((*it).host == host)
			return true;
	}
	return false;
}

} /* namespace HTTP */
