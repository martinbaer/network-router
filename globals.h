#ifndef GLOBALS_H
#define GLOBALS_H

#include "packet.h"
#include "invocation.h"

typedef struct KNOWN_SWITCH
{
	int socket_fd;
	IP_ADDRESS ip_address;
	int distance;
} KNOWN_SWITCH;

extern int num_known_switches;
extern KNOWN_SWITCH *known_switches;

extern SWITCH this_switch;

#endif
