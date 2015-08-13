/*
 * HTTPSession.h
 *
 *  Created on: 8 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SRC_HTTPSESSION_H_
#define SRC_HTTPSESSION_H_

#include <vector>
#include "HTTP.h"

class HTTPSession {
	std::vector<HTTP*> objects;

public:
	uint16_t 	 port;
	uint32_t 	 addr;
	std::string  hostUrl;
	bool		 complete;

	HTTPSession(HTTP* http);
	HTTPSession(unsigned int sport, unsigned int dport, unsigned int src, HTTP* request);
	virtual ~HTTPSession();

	void newRequest(HTTP* http);
	void addRequestResponse(uint32_t addr, uint16_t sport, int len, unsigned char* response);

};

#endif /* SRC_HTTPSESSION_H_ */
