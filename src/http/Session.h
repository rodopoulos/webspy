/*
 * Session.h
 *
 *  Created on: 21 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef HTTP_SESSION_H_
#define HTTP_SESSION_H_

#include <list>
#include <string>

#include "HTTP.h"

namespace HTTP {

class Session {
	static long int idGen;

public:
	std::list<Response> content;
	std::string host, path;
	int			status;
	long int 	id;

	Session(std::string host, std::string path);
	Session(Response http);
	virtual ~Session();

	void	  addContent(Response content);
	Response  popRootHTML();
	Response  popRequestedElement(std::string uri);
	bool      operator == (Session& a);

	static const int RECEIVING = 0;
	static const int READY	  	= 1;
	static const int DONE	  	= 2;
};

} /* namespace HTTP */

#endif /* HTTP_SESSION_H_ */
