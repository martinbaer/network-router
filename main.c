

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "invocation.h"
#include "open_port.h"
#include "packet.h"
#include "connect_switch.h"
#include "connect_adapter.h"

#include "globals.h"

SWITCH this_switch = {0};
int num_neighbour_switches = 0;
NeighbourSwitch *neighbour_switches = NULL;
int num_neighbour_adapters = 0;
NeighbourAdaptor *neighbour_adapters = NULL;
int num_known_ip_addresses = 0;
KnownIpAddress *known_ip_addresses = NULL;

int main(int argc, char *argv[])
{
	this_switch = parse_command_line(argc, argv);
	neighbour_switches = malloc(sizeof(NeighbourSwitch) * num_neighbour_switches);
	neighbour_adapters = malloc(sizeof(NeighbourAdaptor) * num_neighbour_adapters);
	known_ip_addresses = malloc(sizeof(KnownIpAddress) * num_known_ip_addresses);
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
		pthread_create(&listen_for_adaptor_connections_thread, NULL, listen_for_adapter_connections, socket_fd_heap);
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
