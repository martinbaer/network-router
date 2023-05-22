#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "data_forwarding.h"
#include "distance_relaying.h"

#define TCP_BUFFER_SIZE 1500

void handle_received_distance(PACKET packet, KNOWN_SWITCH neighbour_switch);
void handle_received_data(PACKET packet, BYTE packet_bytes[TCP_BUFFER_SIZE], KNOWN_SWITCH neighbour_switch);
void handle_query(PACKET packet, KNOWN_SWITCH neighbour_switch);
int get_prefix_length(IP_ADDRESS ip1, IP_ADDRESS ip2);

void listen_and_forward(KNOWN_SWITCH neighbour_switch)
{
	BYTE buffer[TCP_BUFFER_SIZE];
	while (1)
	{
		fprintf(stderr, "Listening for packets\n");
		fflush(stderr);
		memset(buffer, 0, TCP_BUFFER_SIZE);
		if (recv(neighbour_switch.socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
		{
			perror("recv failed");
		}
		PACKET packet = bytes_to_packet(buffer);
		if (packet.mode == DISTANCE)
		{
			fprintf(stderr, "Received DISTANCE packet\n");
			fflush(stderr);
			handle_received_distance(packet, neighbour_switch);
			fprintf(stderr, "Completed handling DISTANCE packet\n");
			fflush(stderr);
		}
		else if (packet.mode == DATA)
		{
			fprintf(stderr, "Received DATA packet\n");
			fflush(stderr);
			handle_received_data(packet, buffer, neighbour_switch);
			fprintf(stderr, "Completed handling DATA packet\n");
			fflush(stderr);
		}
		else if (packet.mode == QUERY)
		{
			fprintf(stderr, "Received QUERY packet\n");
			fflush(stderr);
			handle_query(packet, neighbour_switch);
			fprintf(stderr, "Completed handling QUERY packet\n");
			fflush(stderr);
		}
		else
		{
			fprintf(stderr, "Received unknown packet, mode: %d\n", packet.mode);
			fflush(stderr);
		}
	}
}

void handle_query(PACKET packet, KNOWN_SWITCH neighbour_switch)
{
	// reply with a READY packet
	PACKET ready_packet = new_packet(this_switch.global_ip.ip_address, packet.source_ip, 0, READY, NULL);
	BYTE *ready_packet_bytes = packet_to_bytes(ready_packet);
	if (send(neighbour_switch.socket_fd, ready_packet_bytes, 12, 0) < 0)
	{
		perror("send failed");
	}
}

// Data is sent from adapters to switches and other adapters in Data packets (Mode = 0x05). Upon receiving a Data packet, the switch will have to forward it to other switches/adapters until it reaches the destination specified in the Destination IP field. These conditions must be followed when deciding which connection to forward the packet to:
// • If the packet is intended for an adapter which the switch is connected to, it will forward the packet to that adapter.
// • If the switch is aware of the existence destination IP address, it should forward the packet to whichever connection is on the shortest geographical path to the destination.
// • If two or more neighbouring switches are on paths of the same shortest length to the destination, the switch amongst these with the longest matching prefix of the destination IP address should receive the packet.
// • If the switch is unaware of the existence of the destination IP address, it should forward the packet to whichever of its neighbouring connections has the IP address with the longest matching prefix with the destination IP address.
void handle_received_data(PACKET packet, BYTE packet_bytes[TCP_BUFFER_SIZE], KNOWN_SWITCH neighbour_switch)
{
	// If the packet is intended for an adapter which the switch is connected to, it will forward the packet to that adapter.
	for (int i = 0; i < num_known_adapters; i++)
	{
		if (ip_address_equals(known_adapters[i].ip_address, packet.destination_ip))
		{
			//  SEND TO END POINT
			// check if already ready and send
			time_t current_time = time(NULL);
			if (difftime(current_time, known_adapters[i].time_of_last_ready) < 5)
			{
				// ready
				if (sendto(known_adapters[i].socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0, (struct sockaddr *)&known_adapters[i].client_addr, known_adapters[i].client_addr_len) < 0)
				{
					perror("sendto failed");
				}
				return;
			}
			// PACKET new_packet(IP_ADDRESS source_ip, IP_ADDRESS destination_ip, unsigned int offset, MODE mode, BYTE *data)
			// send query packet
			PACKET query_packet = new_packet(this_switch.local_ip.ip_address, packet.destination_ip, 0, QUERY, NULL);
			BYTE *query_packet_bytes = packet_to_bytes(query_packet);
			if (sendto(known_adapters[i].socket_fd, query_packet_bytes, 12, 0, (struct sockaddr *)&known_adapters[i].client_addr, known_adapters[i].client_addr_len) < 0)
			{
				perror("sendto failed");
			}
			// receive response packet
			BYTE response_packet_bytes[TCP_BUFFER_SIZE];
			if (recv(known_adapters[i].socket_fd, response_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
			{
				perror("recv failed");
			}
			PACKET response_packet = bytes_to_packet(response_packet_bytes);
			if (response_packet.mode != READY)
			{
				printf("ERROR: Received packet was not a READY packet\n");
				return;
			}
			known_adapters[i].time_of_last_ready = time(NULL);
			// send data
			if (sendto(known_adapters[i].socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0, (struct sockaddr *)&known_adapters[i].client_addr, known_adapters[i].client_addr_len) < 0)
			{
				perror("sendto failed");
			}
			return;
		}
	}
	// If the switch is aware of the existence destination IP address, it should forward the packet to whichever connection is on the shortest geographical path to the destination.
	for (int i = 0; i < num_known_switches; i++)
	{
		if (ip_address_equals(known_switches[i].ip_address, packet.destination_ip))
		{
			// check if next hop is equal to the switch - SEND TO END POINT
			if (ip_address_equals(known_switches[i].next_hop, packet.destination_ip))
			{
				// check if already ready and send
				time_t current_time = time(NULL);
				if (difftime(current_time, known_switches[i].time_of_last_ready) < 5)
				{
					// ready
					if (send(known_switches[i].socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
					{
						perror("send failed");
					}
					return;
				}
				// send query packet
				fprintf(stderr, "Sending query packet to switch\n");
				fflush(stderr);
				PACKET query_packet = new_packet(this_switch.local_ip.ip_address, packet.destination_ip, 0, QUERY, NULL);
				BYTE *query_packet_bytes = packet_to_bytes(query_packet);
				if (send(known_switches[i].socket_fd, query_packet_bytes, 12, 0) < 0)
				{
					perror("send failed");
				}
				// receive response packet
				BYTE response_packet_bytes[TCP_BUFFER_SIZE];
				if (recv(known_switches[i].socket_fd, response_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
				{
					perror("recv failed");
				}
				PACKET response_packet = bytes_to_packet(response_packet_bytes);
				print_packet(response_packet);
				if (response_packet.mode != READY)
				{
					printf("ERROR: Received packet was not a READY packet\n");
					return;
				}
				known_switches[i].time_of_last_ready = time(NULL);
				// send data
				if (send(known_switches[i].socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
				{
					perror("send failed");
				}
				return;
			}
			// forward to next hop
			if (send(known_switches[i].next_hop_socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
			{
				perror("send failed");
			}
			return;
		}
	}
	// If the switch is unaware of the existence of the destination IP address, it should forward the packet to whichever of its neighbouring connections has the IP address with the longest matching prefix with the destination IP address.
	int best_neighbour_socket_fd = -1;
	int best_prefix_length = -1;
	for (int i = 0; i < num_known_switches; i++)
	{
		// check if neighbour
		if (known_switches[i].socket_fd != known_switches[i].next_hop_socket_fd)
			continue;
		// check if prefix length is better
		int prefix_length = get_prefix_length(known_switches[i].ip_address, packet.destination_ip);
		if (prefix_length > best_prefix_length)
		{
			best_prefix_length = prefix_length;
			best_neighbour_socket_fd = known_switches[i].socket_fd;
		}
	}
	if (best_neighbour_socket_fd == -1)
	{
		fprintf(stderr, "ERROR: No neighbour found\n");
		fflush(stderr);
		return;
	}
	// forward to best neighbour
	if (send(best_neighbour_socket_fd, packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("send failed");
	}
}

// typedef struct IP_ADDRESS
// {
// 	unsigned char octet[4];
// } IP_ADDRESS;
int get_prefix_length(IP_ADDRESS ip1, IP_ADDRESS ip2)
{
	int prefix_length = 0;
	for (int i = 0; i < 4; i++)
	{
		if (ip1.octet[i] == ip2.octet[i])
		{
			prefix_length += 8;
		}
		else
		{
			int difference = ip1.octet[i] ^ ip2.octet[i];
			for (int j = 0; j < 8; j++)
			{
				if (difference & 1)
				{
					return prefix_length;
				}
				difference >>= 1;
				prefix_length++;
			}
		}
	}
	return prefix_length;
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
			if (distance > known_switches[i].distance)
			{
				return;
			}
			// • If two or more neighbouring switches are on paths of the same shortest length to the destination, the switch amongst these with the longest matching prefix of the destination IP address should receive the packet.
			else if (distance == known_switches[i].distance)
			{
				// check which ip has the longest matching prefix (bit by bit)
				int prefix_length_of_new_ip = get_prefix_length(ip_address_of_distance, neighbour_switch.ip_address);
				int prefix_length_of_current_ip = get_prefix_length(known_switches[i].ip_address, neighbour_switch.ip_address);
				if (prefix_length_of_new_ip <= prefix_length_of_current_ip)
				{
					return;
				}
			}
			known_switches[i].distance = distance;
			// set next hop
			for (int j = 0; j < 4; j++)
			{
				known_switches[i].next_hop.octet[j] = neighbour_switch.ip_address.octet[j];
			}
			known_switches[i].socket_fd = neighbour_switch.socket_fd;
			relay_distance(known_switches[i]);
			ip_is_known = true;
			break;
		}
	}
	if (!ip_is_known)
	{
		KNOWN_SWITCH new_switch = add_new_known_switch(neighbour_switch.socket_fd, ip_address_of_distance, distance, neighbour_switch.ip_address, neighbour_switch.socket_fd);
		relay_distance(new_switch);
	}
}
