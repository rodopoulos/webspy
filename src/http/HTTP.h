/*
 * HTTP.h
 *
 *  Created on: 11 de ago de 2015
 *      Author: rodopoulos
 */

#ifndef SRC_HTTP_H_
#define SRC_HTTP_H_

#include <cstring>
#include <string>
#include <sstream>
#include <map>
#include <tins/tins.h>

namespace HTTP {

class Message{
	void parseHeaders();

public:
	char*		data, *body;
	uint32_t	srvAddr;
	uint16_t	srvPort;
	std::string uri;
	std::map<std::string, std::string> headers;


	Message(unsigned char* payload, std::size_t size);
	virtual ~Message();
	Message(Tins::IPv4Address srvAddr, uint16_t srvPort, unsigned char* payload, std::size_t size);
	std::string	getHeader(const std::string key);
	bool		hasHeader(const std::string key);
	void		stripHeader(const std::string key);
	void		alterHeader(const std::string key, const std::string input);
	std::size_t dataSize();
	void		setServer(Tins::IPv4Address addr, uint16_t port);
	void		setURI(std::string uri);
	void		addData(unsigned char* data, int len);
	virtual const char* flushData() = 0;
	virtual void 		toString() = 0;

};

class Request : public Message{
public:
	Request(unsigned char* payload, std::size_t size);
	virtual ~Request();
	const char* flushData();
	void toString();

	static void parseMultipleRequests(std::list<Request*>* content, unsigned char* buf, int len);

	std::string uri;
	std::string method;
	std::string version;
};

class Response : public Message{
public:
	Response(unsigned char* payload, std::size_t size);
	virtual ~Response();
	const char* flushData();
	void toString();

	static void parseMultipleResponses(std::list<Response*>* content, unsigned char* buf, int len);

	std::string code;
	std::string message;
	std::string version;
};

} /* namespace HTTP */

#endif /* SRC_HTTP_H_ */
