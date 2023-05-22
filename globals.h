#ifndef GLOBALS_H
#define GLOBALS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#include "packet.h"
#include "invocation.h"

typedef struct KNOWN_SWITCH
{
	int socket_fd;
	IP_ADDRESS ip_address;
	int distance;
	IP_ADDRESS next_hop;
	int next_hop_socket_fd;
	time_t time_of_last_ready;
} KNOWN_SWITCH;

typedef struct KNOWN_ADAPTOR
{
	int socket_fd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	IP_ADDRESS ip_address;
	time_t time_of_last_ready;
} KNOWN_ADAPTOR;

extern int num_known_switches;
extern KNOWN_SWITCH *known_switches;

extern int num_known_adapters;
extern KNOWN_ADAPTOR *known_adapters;

extern SWITCH this_switch;

#endif
