#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "data_forwarding.h"
#include "distance_relaying.h"

#define TCP_BUFFER_SIZE 1500

void handle_received_distance(PACKET packet, KNOWN_SWITCH neighbour_switch);
void handle_received_data(PACKET packet, KNOWN_SWITCH neighbour_switch);

void listen_and_forward(KNOWN_SWITCH neighbour_switch)
{
	int socket_fd = neighbour_switch.socket_fd;
	IP_ADDRESS ip_address = neighbour_switch.ip_address;
	BYTE buffer[TCP_BUFFER_SIZE];
	while (1)
	{
		memset(buffer, 0, TCP_BUFFER_SIZE);
		if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
		{
			perror("recv failed");
		}
		PACKET packet = bytes_to_packet(buffer);
		if (packet.mode == DISTANCE)
		{
			handle_received_distance(packet, neighbour_switch);
		}
		else if (packet.mode == DATA)
		{
			handle_received_data(packet, neighbour_switch);
		}
	}
}

void handle_received_distance(PACKET packet, KNOWN_SWITCH neighbour_switch)
{
	// extract ip (first 4 bytes of data) and distance (last 4 bytes of data)
	BYTE *ip_bytes = malloc(4);
	BYTE *distance_bytes = malloc(4);
	memcpy(ip_bytes, packet.data, 4);
	memcpy(distance_bytes, packet.data + 4, 4);
	IP_ADDRESS ip_address_of_distance = bytes_to_ip_address(ip_bytes);
	// convert distance byte (big endian) to int
	int distance = 0;
	for (int i = 0; i < 4; i++)
	{
		distance += distance_bytes[i] << (8 * (3 - i));
	}
	// check if ip is already in known switches
	bool ip_is_known = false;
	for (int i = 0; i < num_known_switches; i++)
	{
		if (ip_address_equals(known_switches[i].ip_address, ip_address_of_distance))
		{
			// if distance is greater than or equal to current distance, do nothing
			if (distance >= known_switches[i].distance)
			{
				return;
			}
			known_switches[i].distance = distance;
			relay_distance(known_switches[i]);
			ip_is_known = true;
			break;
		}
	}
	if (!ip_is_known)
	{
		KNOWN_SWITCH new_switch = add_new_known_switch(neighbour_switch.socket_fd, ip_address_of_distance, distance);
		relay_distance(new_switch);
	}
}