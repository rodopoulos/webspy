/*
 * Renderer.h
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#ifndef RENDERER_H_
#define RENDERER_H_

#include <pthread.h>

class Renderer {
	pthread_t rendererThread;
	pthread_mutex_t rendererMutex;
	Crafter rendererCrafter;
	std::queue<Packet> rendererBuffer;

public:
	Renderer();
	virtual ~Renderer();

	void init();

};

#endif /* RENDERER_H_ */
