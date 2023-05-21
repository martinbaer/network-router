#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "packet.h"
#include "ip_allocation.h"
#include "globals.h"

#define UDP_BUFFER_SIZE 1024

void *listen_for_adaptor_connections(void *arg)
{
	// UDP socket file descriptor
	int socket_fd = *(int *)arg;

	// listen for UDP packets
	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		BYTE buffer[UDP_BUFFER_SIZE];
		memset(buffer, 0, UDP_BUFFER_SIZE);
		// receive DISCOVER packet
		if (recvfrom(socket_fd, buffer, UDP_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len) < 0)
		{
			perror("recvfrom failed");
		}
		PACKET discover_packet = bytes_to_packet(buffer);
		if (discover_packet.mode != DISCOVER)
		{
			continue;
		}
		// print discover packet
		print_packet(discover_packet);
		// send OFFER packet
		IP_ADDRESS assigned_ip = allocate_local_ip_address();
		BYTE *assigned_ip_bytes = ip_address_to_bytes(assigned_ip);
		PACKET offer_packet = new_packet(this_switch.global_ip.ip_address, zero_ip_address(), 0, OFFER, assigned_ip_bytes);
		BYTE *offer_packet_bytes = packet_to_bytes(offer_packet);
		if (sendto(socket_fd, offer_packet_bytes, 16, 0, (struct sockaddr *)&client_addr, client_addr_len) < 0)
		{
			perror("sendto failed");
		}
		perror("sent offer");
		// receive REQUEST packet
		memset(buffer, 0, UDP_BUFFER_SIZE);
		if (recvfrom(socket_fd, buffer, UDP_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len) < 0)
		{
			perror("recvfrom failed");
		}
		PACKET request_packet = bytes_to_packet(buffer);
		if (request_packet.mode != REQUEST)
		{
			continue;
		}
		// send ACKNOWLEDGE packet
		PACKET acknowledgment_packet = new_packet(this_switch.global_ip.ip_address, assigned_ip, 0, ACKNOWLEDGE, assigned_ip_bytes);
		BYTE *acknowledgment_packet_bytes = packet_to_bytes(acknowledgment_packet);
		if (sendto(socket_fd, acknowledgment_packet_bytes, UDP_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, client_addr_len) < 0)
		{
			perror("sendto failed");
		}
	}

	return NULL;
}
