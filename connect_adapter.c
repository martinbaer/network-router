#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>

#include "packet.h"
#include "ip_allocation.h"
#include "globals.h"

#define UDP_BUFFER_SIZE 2048

void *listen_for_adapter_connections(void *arg)
{
	// UDP socket file descriptor
	int socket_fd = *(int *)arg;
	fflush(stdout);
	// listen for UDP packets
	while (1)
	{
		struct sockaddr_in client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		Byte buffer[UDP_BUFFER_SIZE];
		memset(buffer, 0, UDP_BUFFER_SIZE);
		int recv_len;
		// receive DISCOVER packet
		if ((recv_len = recvfrom(socket_fd, buffer, UDP_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len)) < 0)
		{
			perror("recvfrom failed");
		}
		Packet discover_packet = bytes_to_packet(buffer);
		if (discover_packet.mode != DISCOVER)
		{
			continue;
		}
		// print discover packet
		// print_packet(discover_packet);
		// send OFFER packet
		IpAddress assigned_ip = allocate_local_ip_address();
		Byte *assigned_ip_bytes = ip_address_to_bytes(assigned_ip);
		Packet offer_packet = new_packet(this_switch.local_ip.ip_address, zero_ip_address(), 0, OFFER, assigned_ip_bytes);
		Byte *offer_packet_bytes = packet_to_bytes(offer_packet);

		if (sendto(socket_fd, offer_packet_bytes, 16, 0, (struct sockaddr *)&client_addr, client_addr_len) < 0)
		{
			perror("sendto failed");
		}
		// perror("sent offer");
		// receive REQUEST packet
		memset(buffer, 0, UDP_BUFFER_SIZE);
		if (recvfrom(socket_fd, buffer, UDP_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, &client_addr_len) < 0)
		{
			perror("recvfrom failed");
		}
		Packet request_packet = bytes_to_packet(buffer);
		if (request_packet.mode != REQUEST)
		{
			continue;
		}
		// send ACKNOWLEDGE packet
		Packet acknowledgment_packet = new_packet(this_switch.local_ip.ip_address, assigned_ip, 0, ACKNOWLEDGE, assigned_ip_bytes);
		Byte *acknowledgment_packet_bytes = packet_to_bytes(acknowledgment_packet);
		if (sendto(socket_fd, acknowledgment_packet_bytes, UDP_BUFFER_SIZE, 0, (struct sockaddr *)&client_addr, client_addr_len) < 0)
		{
			perror("sendto failed");
		}

		// add to known adaptors
		neighbour_adapters = realloc(neighbour_adapters, sizeof(NeighbourAdaptor) * (num_neighbour_adapters + 1));
		neighbour_adapters[num_neighbour_adapters].socket_fd = socket_fd;
		neighbour_adapters[num_neighbour_adapters].client_addr = client_addr;
		neighbour_adapters[num_neighbour_adapters].client_addr_len = client_addr_len;
		// copy assigned_ip_bytes into neighbour_adapters[num_neighbour_adapters].assigned_ip
		neighbour_adapters[num_neighbour_adapters].ip_address.octet[0] = assigned_ip_bytes[0];
		neighbour_adapters[num_neighbour_adapters].ip_address.octet[1] = assigned_ip_bytes[1];
		neighbour_adapters[num_neighbour_adapters].ip_address.octet[2] = assigned_ip_bytes[2];
		neighbour_adapters[num_neighbour_adapters].ip_address.octet[3] = assigned_ip_bytes[3];
		neighbour_adapters[num_neighbour_adapters].time_of_last_ready = time(NULL) - 10;
		num_neighbour_adapters++;

		NeighbourSwitch me_as_neighbour = {0, this_switch.local_ip.ip_address, time(NULL) - 10};
		add_new_known_ip_address(assigned_ip, me_as_neighbour, 0);
	}

	return NULL;
}
