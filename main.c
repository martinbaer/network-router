

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

	PORT tcp_port, udp_port;
	if (this_switch.type == LOCAL || this_switch.type == MIXED)
	{
		// open UDP port
		udp_port = open_port(SOCK_DGRAM);
		printf("%d\n", udp_port.port);
	}
	if (this_switch.type == GLOBAL || this_switch.type == MIXED)
	{
		// open TCP port
		tcp_port = open_port(SOCK_STREAM);
		printf("%d\n", tcp_port.port);
	}

	pthread_t listen_for_commands_thread, listen_for_switch_connections_thread;
	if (this_switch.type == LOCAL || this_switch.type == GLOBAL)
	{
		pthread_create(&listen_for_commands_thread, NULL, listen_for_commands, NULL);
	}
	if (this_switch.type == GLOBAL || this_switch.type == MIXED)
	{

		pthread_create(&listen_for_switch_connections_thread, NULL, listen_for_switch_connections, &tcp_port.socket);
	}

	// wait for threads to finish
	if (this_switch.type == LOCAL || this_switch.type == GLOBAL)
	{
		pthread_join(listen_for_commands_thread, NULL);
	}
	if (this_switch.type == GLOBAL || this_switch.type == MIXED)
	{
		pthread_join(listen_for_switch_connections_thread, NULL);
	}

	return 0;
}
