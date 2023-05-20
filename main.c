

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "invocation.h"
#include "open_port.h"
#include "packet.h"
#include "connect_switch.h"

#include "globals.h"

ALL_CONNECTIONS all_connections = {0};
SWITCH this_switch = {0};

int main(int argc, char *argv[])
{
	this_switch = parse_command_line(argc, argv);

	if (this_switch.type == LOCAL || this_switch.type == MIXED)
	{
		// open UDP port
		PORT udp_port = open_port(SOCK_DGRAM);
		printf("%d\n", udp_port.port);
	}
	if (this_switch.type == GLOBAL || this_switch.type == MIXED)
	{
		// open TCP port
		PORT tcp_port = open_port(SOCK_STREAM);
		printf("%d\n", tcp_port.port);
	}

	if (this_switch.type == LOCAL || this_switch.type == GLOBAL)
	{
		pthread_t listen_for_commands_thread;
		pthread_create(&listen_for_commands_thread, NULL, listen_for_commands, NULL);
	}
	if (this_switch.type == GLOBAL || this_switch.type == MIXED)
	{
		pthread_t listen_for_switch_connections_thread;
		pthread_create(&listen_for_switch_connections_thread, NULL, listen_for_switch_connections, NULL);
	}

	return 0;
}
