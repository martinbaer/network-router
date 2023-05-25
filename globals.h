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

typedef struct KnownIpAddress
{
	IpAddress ip_address;
} KnownIpAddress;

typedef struct NeighbourSwitch
{
	int socket_fd;
	IpAddress ip_address;
	int distance;
	IpAddress next_hop;
	int next_hop_socket_fd;
	time_t time_of_last_ready;
	IpAddress distance_informant_ip_address;
} NeighbourSwitch;

typedef struct NeighbourAdaptor
{
	int socket_fd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	IpAddress ip_address;
	time_t time_of_last_ready;
} NeighbourAdaptor;

extern int num_known_switches;
extern NeighbourSwitch *known_switches;

extern int num_known_adapters;
extern NeighbourAdaptor *known_adapters;

extern SWITCH this_switch;

#endif
