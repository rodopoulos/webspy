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

class HTTP{
#define HTTP_REQ 		 1
#define HTTP_RES 		 2
#define HTTP_T_HTML 	 1
#define HTTP_T_JS		 2
#define HTTP_T_CSS		 3
#define HTTP_T_IMG		 4
#define HTTP_T_JSDATA	 5
#define HTTP_T_NONE 	 6

public:
	char*		data;
	uint32_t	srvAddr;
	uint16_t	srvPort;
	int 		len;
	int			op;

	std::string	host, referer;
	std::string	path;
	int 		contentLenght;
	int			contentType;

	HTTP(uint32_t srvAddr, uint16_t srvPort, unsigned char* payload);
	static std::string retrieveHeaderValue(unsigned char* data, char* key);
	static std::string retrieveObjectPath(unsigned char* data);
	static int		   readMethod(char* payload);
	static int		   getContentTypeCode(std::string type);

	void 		setResponseContent(unsigned char* content, int len);
	void 		setNoCache();
	void 		setNoCookieEncoding();

	void  stripSSL();

};

#endif /* SRC_HTTP_H_ */
