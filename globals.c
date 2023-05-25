#include "globals.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

// --- LOCAL FUNCTIONS ---
KnownIpAddress create_known_ip_address(IpAddress new_ip_address, NeighbourSwitch next_hop, int distance);
NeighbourSwitch create_neighbour_switch(int socket_fd, IpAddress ip_address);
// -----------------------

KnownIpAddress *find_known_ip_address(IpAddress ip_address)
{
	for (int i = 0; i < num_known_ip_addresses; i++)
	{
		if (ip_address_equals(known_ip_addresses[i].ip_address, ip_address))
		{
			return &known_ip_addresses[i];
		}
	}
	return NULL;
}

NeighbourSwitch add_new_neighbour_switch(int socket_fd, IpAddress ip_address, int distance)
{
	// create new neighbour switch
	NeighbourSwitch new_switch = create_neighbour_switch(socket_fd, ip_address);
	neighbour_switches = realloc(neighbour_switches, sizeof(NeighbourSwitch) * (num_neighbour_switches + 1));
	neighbour_switches[num_neighbour_switches] = new_switch;
	num_neighbour_switches++;
	// add neighbour switch to known ip addresses
	KnownIpAddress known_ip_address = create_known_ip_address(ip_address, new_switch, distance);
	known_ip_addresses = realloc(known_ip_addresses, sizeof(IpAddress) * (num_known_ip_addresses + 1));
	known_ip_addresses[num_known_ip_addresses] = known_ip_address;
	num_known_ip_addresses++;

	return new_switch;
}

NeighbourSwitch create_neighbour_switch(int socket_fd, IpAddress ip_address)
{
	NeighbourSwitch result;
	result.socket_fd = socket_fd;
	result.time_of_last_ready = time(NULL) - 10;
	// copy ip address
	for (int i = 0; i < 4; i++)
	{
		result.ip_address.octet[i] = ip_address.octet[i];
	}
	// calulcate euclidean distance from this_switch.latitude and this_switch.longitude
	return result;
}

KnownIpAddress create_known_ip_address(IpAddress new_ip_address, NeighbourSwitch next_hop, int distance)
{
	KnownIpAddress result;
	for (int i = 0; i < 4; i++)
	{
		result.ip_address.octet[i] = new_ip_address.octet[i];
	}
	result.next_hop = next_hop;
	result.distance = distance;
	return result;
}

void add_new_known_ip_address(IpAddress ip_address, NeighbourSwitch next_hop, int distance)
{
	KnownIpAddress new_known_ip_address = create_known_ip_address(ip_address, next_hop, distance);
	known_ip_addresses = realloc(known_ip_addresses, sizeof(KnownIpAddress) * (num_known_ip_addresses + 1));
	known_ip_addresses[num_known_ip_addresses] = new_known_ip_address;
	num_known_ip_addresses++;
}