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

typedef struct NeighbourSwitch
{
	int socket_fd;
	IpAddress ip_address;
	time_t time_of_last_ready;
} NeighbourSwitch;

typedef struct NeighbourAdaptor
{
	int socket_fd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	IpAddress ip_address;
	time_t time_of_last_ready;
} NeighbourAdaptor;

typedef struct KnownIpAddress
{
	IpAddress ip_address;
	NeighbourSwitch next_hop;
	int distance;
} KnownIpAddress;

extern int num_neighbour_switches;
extern NeighbourSwitch *neighbour_switches;

extern int num_neighbour_adapters;
extern NeighbourAdaptor *neighbour_adapters;

extern int num_known_ip_addresses;
extern KnownIpAddress *known_ip_addresses;

KnownIpAddress *find_known_ip_address(IpAddress ip_address);

void add_new_known_ip_address(IpAddress ip_address, NeighbourSwitch next_hop, int distance);

extern SWITCH this_switch;

#endif
