/*
 * Renderer.cpp
 *
 *  Created on: Apr 7, 2015
 *      Author: Felipe Rodopoulos
 */

#include "Renderer.h"

Renderer::Renderer() {
}

Renderer::~Renderer() {
	// TODO Auto-generated destructor stub
}

Renderer::init(){
	if(pthread_mutex_init(&rendererMutex, NULL) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init relay thread\n");
		exit(EXIT_FAILURE);
	}
	if(pthread_create(&rendererThread, nullptr, rendererBuffer, nullptr) < 0){
		printf("Webspy::Pipe::init > [ERRO] can't init victim relayer thread\n");
		exit(EXIT_FAILURE);
	}
}
