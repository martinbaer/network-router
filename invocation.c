// The switch takes the following commandline arguments in order:
// • Its type (local/global)
// • Its IP address(es) with CIDR notation
// • Its latitude
// • Its longitude
// where the latitude and longitude are positive nonnegative integers no greater than 32767.
// 3
// The below commands are used to start a local switch:
// $ python3 RUSHBSwitch . py local ip_address / cidr latitude longitude
// $ ./ RUSHBSwitch local ip_address / cidr latitude longitude
// for example:
// $ ./ RUSHBSwitch local 192 .168. 0.1/2 4 50 20
// The below commands are used to start a mixed switch:
// $ python3 RUSHBSwitch . py local l o c a l _ i p _ a d d r e s s / cidr g l o b a l _ i p _ a d d r e s s / cidr latitude longitude
// $ ./ RUSHBSwitch local l o c a l _i p _ a d d r e s s / cidr g l o b a l _ i p _ a d d r e s s / cidr latitude longitude
// for example:
// $ ./ RUSHBSwitch local 192 .168. 0.1/2 4 1 3 0 . 1 0 2 . 7 2 . 1 0 / 2 4 50 20
// The below commands are used to start a global switch:
// $ python3 RUSHBSwitch . py global ip_address / cidr latitude longitude
// $ ./ RUSHBSwitch global ip_address / cidr latitude longitude
// for example:
// $ ./ RUSHBSwitch global 1 3 0 . 10 2 . 7 2 . 1 0 / 2 4 50 20
// If the incorrect number of arguments are given, or any argument is invalid in any way, the switch will exit
// immediately.

#include "invocation.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// typedef struct IP_ADDRESS_WITH_CIDR
// {
// 	IP_ADDRESS ip_address;
// 	unsigned char cidr;
// } IP_ADDRESS_WITH_CIDR;
// typedef struct IP_ADDRESS
// {
// 	unsigned char octet[4];
// } IP_ADDRESS;
// parse from form e.g. 168.0.0.1/24
IP_ADDRESS_WITH_CIDR parse_ip_address(char *ip_address_str)
{
	IP_ADDRESS_WITH_CIDR result;
	int octets[4];
	int cidr;

	// sscanf returns the number of successfully read items
	if (sscanf(ip_address_str, "%d.%d.%d.%d/%d", &octets[0], &octets[1], &octets[2], &octets[3], &cidr) != 5)
	{
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < 4; ++i)
	{
		result.ip_address.octet[i] = octets[i];
	}

	result.cidr = cidr;
	return result;
}

SWITCH parse_command_line(int argc, char *argv[])
{
	SWITCH sw;
	// get switch type
	if (argc == 5)
	{
		// check if local or global
		if (strcmp(argv[1], "local") == 0)
		{
			sw.type = LOCAL;
		}
		else if (strcmp(argv[1], "global") == 0)
		{
			sw.type = GLOBAL;
		}
		else
		{
			printf("Invalid switch type (a)\n");
			exit(1);
		}
	}
	else if (argc == 6)
	{
		sw.type = MIXED;
		// check that first argument is local
		if (strcmp(argv[1], "local") != 0)
		{
			printf("Invalid switch type (b)\n");
			exit(1);
		}
	}
	else
	{
		printf("Invalid number of arguments\n");
		exit(1);
	}
	// get local ip address
	if (sw.type == LOCAL || sw.type == MIXED)
	{
		// at index 2
		sw.local_ip = parse_ip_address(argv[2]);
	}
	// get global ip address
	if (sw.type == MIXED)
	{
		// at index 4
		sw.global_ip = parse_ip_address(argv[4]);
	}
	else if (sw.type == GLOBAL)
	{
		// at index 2
		sw.global_ip = parse_ip_address(argv[2]);
	}
	// get latitude
	sw.location.x = atoi(argv[argc - 2]);
	// get longitude
	sw.location.y = atoi(argv[argc - 1]);

	// set num_assigned_global_ips and num_assigned_local_ips to 0
	sw.num_assigned_global_ips = 0;
	sw.num_assigned_local_ips = 0;

	// set max_num_assigned_global_ips and max_num_assigned_local_ips
	// 2 ^ (32 - CIDR)
	sw.max_num_assigned_global_ips = (1 << (32 - sw.global_ip.cidr)) - 3;
	sw.max_num_assigned_local_ips = (1 << (32 - sw.local_ip.cidr)) - 3;
	return sw;
}
