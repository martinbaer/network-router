

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "invocation.h"
#include "open_port.h"
#include "packet.h"
#include "connect_switch.h"
#include "connect_adaptor.h"

#include "globals.h"

SWITCH this_switch = {0};
int num_known_switches = 0;
KNOWN_SWITCH *known_switches = NULL;

int main(int argc, char *argv[])
{
	this_switch = parse_command_line(argc, argv);
	known_switches = malloc(sizeof(KNOWN_SWITCH) * num_known_switches);

	PORT tcp_port, udp_port;
	if (this_switch.type == LOCAL || this_switch.type == MIXED)
	{
		// open UDP port
		udp_port = open_port(SOCK_DGRAM);
		printf("%d\n", udp_port.port);
		fflush(stdout);
	}
	if (this_switch.type == GLOBAL || this_switch.type == MIXED)
	{
		// open TCP port
		tcp_port = open_port(SOCK_STREAM);
		printf("%d\n", tcp_port.port);
		fflush(stdout);
	}

	pthread_t listen_for_commands_thread, listen_for_switch_connections_thread, listen_for_adaptor_connections_thread;
	if (this_switch.type == LOCAL || this_switch.type == GLOBAL)
	{
		pthread_create(&listen_for_commands_thread, NULL, listen_for_commands, NULL);
	}
	if (this_switch.type == GLOBAL || this_switch.type == MIXED)
	{
		int *socket_fd_heap = malloc(sizeof(int));
		*socket_fd_heap = tcp_port.socket;
		pthread_create(&listen_for_switch_connections_thread, NULL, listen_for_switch_connections, socket_fd_heap);
	}
	if (this_switch.type == LOCAL || this_switch.type == MIXED)
	{
		int *socket_fd_heap = malloc(sizeof(int));
		*socket_fd_heap = udp_port.socket;
		pthread_create(&listen_for_adaptor_connections_thread, NULL, listen_for_adaptor_connections, socket_fd_heap);
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
