/*
 * Session.cpp
 *
 *  Created on: 21 de ago de 2015
 *      Author: rodopoulos
 */

#include "Session.h"

namespace HTTP {

long int Session::idGen = 1;

Session::Session(std::string host, std::string path)
: host(host), path(path), status(RECEIVING) {
	id = idGen;
	idGen++;
}

Session::~Session() {}

void Session::addContent(Response content){
	this->content.push_back(content);
}

Response Session::popRequestedElement(std::string requested){
	for(auto it = content.begin(); it != content.end(); it++){
		if((*it).uri == requested){
			Response html = *it;
			content.erase(it);
			return html;
		} else continue;
	}
	std::exception e;
	throw e;
}

Response Session::popRootHTML(){
	for(auto it = content.begin(); it != content.end(); it++){
		if((*it).hasHeader("Content-Type")){
			std::string contentType = (*it).getHeader("Content-Type");
			if(contentType.find("text/html") != std::string::npos) {
				Response html = *it;
				content.erase(it);
				return html;
			} else continue;
		} else continue;
	}
	std::exception e;
	throw e;
}

bool Session::operator==(Session& a){
	return id == a.id;
}

} /* namespace HTTP */
