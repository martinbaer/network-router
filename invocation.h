#ifndef INVOCATION_H
#define INVOCATION_H

#include "packet.h"

typedef enum SWITCH_TYPE
{
	LOCAL,
	GLOBAL,
	MIXED
} SWITCH_TYPE;

typedef struct IP_ADDRESS_WITH_CIDR
{
	IpAddress ip_address;
	unsigned char cidr;
} IP_ADDRESS_WITH_CIDR;

typedef struct SWITCH
{
	SWITCH_TYPE type;
	IP_ADDRESS_WITH_CIDR local_ip;
	IP_ADDRESS_WITH_CIDR global_ip;
	int num_assigned_global_ips;
	int max_num_assigned_global_ips;
	int num_assigned_local_ips;
	int max_num_assigned_local_ips;
	Coordinate location;
} SWITCH;

SWITCH parse_command_line(int argc, char *argv[]);

#endif
