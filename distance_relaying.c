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

#define TCP_BUFFER_SIZE 1500

void inform_switch_of_known_distances(NeighbourSwitch known_switch)
{
	// // send known_switch the distances of all other known switches
	// for (int i = 0; i < num_known_switches; i++)
	// {
	// 	NeighbourSwitch other_known_switch = known_switches[i];
	// 	if (!known_switch_equals(known_switch, other_known_switch))
	// 	{
	// 		Packet other_known_switch_distance_packet = new_packet(known_switch.ip_address, other_known_switch_next_hop, 0, DISTANCE, other_known_switch_distance_packet_data);
	// 		Byte *other_known_switch_distance_packet_bytes = packet_to_bytes(other_known_switch_distance_packet);
	// 		if (send(known_switch.socket_fd, other_known_switch_distance_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
	// 		{
	// 			perror("send failed");
	// 		}
	// 	}
	// }
}

NeighbourSwitch create_neighbour_switch(int socket_fd, IpAddress ip_address, int new_switch_distance, IpAddress next_hop, int next_hop_socket_fd, IpAddress distance_informant_ip_address);

bool known_switch_equals(NeighbourSwitch switch1, NeighbourSwitch switch2)
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
void relay_distance(NeighbourSwitch subject, NeighbourSwitch informant)
{

	// send distance to all known switches except subject and informant
	for (int i = 0; i < num_known_switches; i++)
	{
		if (!known_switch_equals(known_switches[i], subject) && !known_switch_equals(known_switches[i], informant))
		{
			if (ip_address_equals(known_switches[i].ip_address, subject.distance_informant_ip_address))
			{
				continue;
			}
			// print informant ip address
			fprintf(stderr, "known switch to relay to: \n");
			for (int j = 0; j < 4; j++)
			{
				fprintf(stderr, "%d.", known_switches[i].ip_address.octet[j]);
			}
			fprintf(stderr, "informant ip address: \n");
			for (int j = 0; j < 4; j++)
			{
				fprintf(stderr, "%d.", informant.ip_address.octet[j]);
			}
			fprintf(stderr, "subject ip address: \n");
			for (int j = 0; j < 4; j++)
			{
				fprintf(stderr, "%d.", subject.ip_address.octet[j]);
			}

			// calculate distance
			int distance = subject.distance + known_switches[i].distance;
			// if distance is greater than 1000, do nothing
			if (distance >= 1000)
			{
				continue;
			}
			// convert distance to bytes (big endian)
			Byte data_field[8];
			data_field[4] = (distance >> 24) & 0xFF;
			data_field[5] = (distance >> 16) & 0xFF;
			data_field[6] = (distance >> 8) & 0xFF;
			data_field[7] = distance & 0xFF;
			// set first 4 bytes to sender's ip address
			for (int j = 0; j < 4; j++)
			{
				data_field[j] = subject.ip_address.octet[j];
			}
			// create packet
			// Packet new_packet(IpAddress source_ip, IpAddress destination_ip, unsigned int offset, Mode mode, Byte *data);
			Packet packet = new_packet(this_switch.global_ip.ip_address, known_switches[i].ip_address, 0, DISTANCE, data_field);
			Byte *packet_bytes = packet_to_bytes(packet);
			// send packet
			if (send(known_switches[i].socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
			{
				perror("send failed");
			}
			free(packet_bytes);
		}
	}
}

int calculate_distance(Coordinate location1, Coordinate location2)
{
	return (int)sqrt(pow(location1.x - location2.x, 2) + pow(location1.y - location2.y, 2));
}

NeighbourSwitch add_new_known_switch(int socket_fd, IpAddress ip_address, int new_switch_distance, IpAddress next_hop, int next_hop_socket_fd, IpAddress distance_informant_ip_address)
{
	NeighbourSwitch new_switch = create_neighbour_switch(socket_fd, ip_address, new_switch_distance, next_hop, next_hop_socket_fd, distance_informant_ip_address);
	known_switches = realloc(known_switches, sizeof(NeighbourSwitch) * (num_known_switches + 1));
	known_switches[num_known_switches] = new_switch;
	num_known_switches++;
	return new_switch;
}

NeighbourSwitch create_neighbour_switch(int socket_fd, IpAddress ip_address, int new_switch_distance, IpAddress next_hop, int next_hop_socket_fd, IpAddress distance_informant_ip_address)
{
	NeighbourSwitch result;
	result.socket_fd = socket_fd;
	result.distance = new_switch_distance;
	result.time_of_last_ready = time(NULL) - 10;
	result.next_hop_socket_fd = next_hop_socket_fd;
	// copy ip address
	for (int i = 0; i < 4; i++)
	{
		result.ip_address.octet[i] = ip_address.octet[i];
	}
	// set next hop ip address
	for (int i = 0; i < 4; i++)
	{
		result.next_hop.octet[i] = next_hop.octet[i];
	}
	// set distance informant ip address
	for (int i = 0; i < 4; i++)
	{
		result.distance_informant_ip_address.octet[i] = distance_informant_ip_address.octet[i];
	}
	// calulcate euclidean distance from this_switch.latitude and this_switch.longitude
	return result;
}
