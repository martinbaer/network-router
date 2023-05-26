#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <stdbool.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "distance_relaying.h"
#include "globals.h"

#define TCP_BUFFER_SIZE 1500

// --- LOCAL FUNCTIONS ---
NeighbourSwitch create_neighbour_switch(int socket_fd, IpAddress ip_address);
KnownIpAddress create_known_ip_address(IpAddress new_ip_address, NeighbourSwitch next_hop, int distance);
// -----------------------

Packet create_distance_packet(IpAddress source, IpAddress destination, IpAddress subject, int distance)
{
	Byte *data_field = malloc(sizeof(Byte) * 8);
	data_field[4] = (distance >> 24) & 0xFF;
	data_field[5] = (distance >> 16) & 0xFF;
	data_field[6] = (distance >> 8) & 0xFF;
	data_field[7] = distance & 0xFF;
	for (int i = 0; i < 4; i++)
	{
		data_field[i] = subject.octet[i];
	}
	// print data field
	Packet result = new_packet(source, destination, 0, DISTANCE, data_field);
	return result;
}

void inform_neighbour_switch_of_known_distances(NeighbourSwitch new_neighbour)
{
	KnownIpAddress *known_ip_address = find_known_ip_address(new_neighbour.ip_address);
	int distance = known_ip_address->distance;
	// send known_switch the distances of all other known switches
	for (int i = 0; i < num_known_ip_addresses; i++)
	{
		// print known ip address
		if (!ip_address_equals(known_ip_addresses[i].ip_address, new_neighbour.ip_address))
		{
			// print ip address
			fprintf(stderr, "Sending distance of %d.%d.%d.%d\n", known_ip_addresses[i].ip_address.octet[0], known_ip_addresses[i].ip_address.octet[1], known_ip_addresses[i].ip_address.octet[2], known_ip_addresses[i].ip_address.octet[3]);
			fflush(stderr);
			Packet packet = create_distance_packet(this_switch.global_ip.ip_address, new_neighbour.ip_address, known_ip_addresses[i].ip_address, distance);
			Byte *packet_bytes = packet_to_bytes(packet);
			print_packet_as_bytes(packet);
			// send packet
			if (send(neighbour_switches[i].socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
			{
				perror("send failed");
			}
			free(packet_bytes);
		}
	}
}

bool neighbour_switch_equals(NeighbourSwitch switch1, NeighbourSwitch switch2)
{
	for (int i = 0; i < 4; i++)
	{
		if (switch1.ip_address.octet[i] != switch2.ip_address.octet[i])
		{
			return false;
		}
	}
	return true;
}

// Whenever a switch receives a Location packet, it will inform all other neighbouring switches of the distance (rounded down) from the new switch to the respective neighbour on the path going through through the switch which received the location packet.
// The switch will send a Distance packet (mode = 0x09) to every connected switch except that which sent it the Location packet. The Source IP field will contain the IP address of the switch which received the Location packet; the Destination IP field will contain the global or assigned IP (whichever applicable) of the neigh- bour which the packet will be sent to and the Offset field will be 0. The first four bytes of the Data field will contain the assigned IP of the switch which sent the Location packet and the second four bytes will con- tain the distance from the switch which sent the Location packet to the neighbouring switch specified in the Destination IP field. This distance is equal to the length of the shortest path from the switch specified in the Data field to the sending switch field plus the Euclidean distance between the sending and receiving switches.
// Switches must maintain a record of the length of the shortest path to every other known IP Address (and hence switch) it has encountered either via distance mode packets or broadcast mode packets. In this as- signment, although we do not explicitly test how you maintain records, it is possible to maintain records of multiple IP’s of the same switch. When a switch receives a Distance packet, if the distance to the switch specified in the Data field is less than its current record, then that record will be updated to the new shortest distance. That switch will then also send a Distance packet to each neighbouring switch except those specified in the Source IP and Data fields. The Data field will contain the same target IP, but will contain the distance from the target IP to the respective neighbour (i.e. the original distance plus the distance to the respective neighbour).
// In the case of a mixed switch, after the greeting protocols and location exchange, the mixed switch must send a distance packet with a target IP of it’s local UDP IP Address (Local IP) the newly connected switch. The distance field of the packet is the distance from the local switch to the new connected switch
// If the distance specified in the packet is greater than or equal to the existing distance record, or if the distance is greater than 1000, the switch will do nothing.
void relay_distance(KnownIpAddress subject, NeighbourSwitch informant)
{
	fprintf(stderr, "Relaying distance\n");
	fflush(stderr);
	// send distance to all neighbour switches except subject and informant
	for (int i = 0; i < num_neighbour_switches; i++)
	{
		if (!ip_address_equals(neighbour_switches[i].ip_address, subject.ip_address) && !ip_address_equals(neighbour_switches[i].ip_address, informant.ip_address))
		{
			KnownIpAddress *neighbour_known_ip_address = find_known_ip_address(neighbour_switches[i].ip_address);
			// print neighbout known ip address
			fprintf(stderr, "Neighbour known ip address: %d.%d.%d.%d\n", neighbour_known_ip_address->ip_address.octet[0], neighbour_known_ip_address->ip_address.octet[1], neighbour_known_ip_address->ip_address.octet[2], neighbour_known_ip_address->ip_address.octet[3]);
			// calculate distance
			int distance = subject.distance + neighbour_known_ip_address->distance;
			// print distance calculation
			fprintf(stderr, "Distance calculation: %d + %d = %d\n", subject.distance, neighbour_known_ip_address->distance, distance);
			// if distance is greater than 1000, do nothing
			if (distance >= 1000)
			{
				continue;
			}
			Packet packet = create_distance_packet(this_switch.global_ip.ip_address, neighbour_switches[i].ip_address, subject.ip_address, distance);
			Byte *packet_bytes = packet_to_bytes(packet);
			// send packet
			fprintf(stderr, "sending...\n");
			if (send(neighbour_switches[i].socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
			{
				perror("send failed");
			}
			free(packet_bytes);
		}
	}
	fprintf(stderr, "Finished relaying distance\n");
	fflush(stderr);
}

int calculate_distance(Coordinate location1, Coordinate location2)
{
	return (int)sqrt(pow(location1.x - location2.x, 2) + pow(location1.y - location2.y, 2));
}
