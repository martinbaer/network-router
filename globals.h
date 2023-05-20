#ifndef GLOBALS_H
#define GLOBALS_H

#include "packet.h"

// struct to be shared
typedef struct ALL_CONNECTIONS
{
	// IP_ADDRESS *ip_addresses;
	int num_connections;
} ALL_CONNECTIONS;

extern ALL_CONNECTIONS all_connections;

#endif
