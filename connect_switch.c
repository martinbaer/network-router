#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globals.h"

#define COMMAND_BUFFER_SIZE 50
#define TCP_BUFFER_SIZE 1000

#define LOCALHOST "127.0.0.1"

IP_ADDRESS n_higher_ip_address(IP_ADDRESS ip_address, int n);

// 	If the switch is able to connect to the port given in the connect command, it (referred to as the client switch)
// will engage in the Greeting Protocol with the switch it connected to (referred to as the host switch). In the
// context of the Greeting Protocol, the Data field is always 4B long and is referred to as the Assigned IP field.
// The protocol works as follows:
// • The client switch sends the host switch a Discovery packet (Mode = 0x01). The Source IP, Destination
// IP, Assigned IP and Offset fields are left at 0.
// • The host switch sends the client switch an Offer packet (Mode = 0x02). The Source IP field is set to the
// global IP of the host switch and the Assigned IP field is set to the IP address the host switch wishes to
// allocate to the client (further details in Section 4.4.6). The Destination IP and Offset fields should still
// remain as 0.
// • The client switch sends the host switch a Request packet (Mode = 0x03). The Source IP and Offset fields
// are set to 0. The Destination IP address is set to the global IP of the host switch and the Assigned IP
// field is set to the IP offered by the host switch in the previous step.
// • The host switch sends the client switch an Acknowledgment packet (Mode = 0x04). The Source IP field
// is set to the global IP of the host switch. The Destination IP and Assigned IP fields are set to the IP
// offered by the host switch. The Offset field is set to 0.

int create_outgoing_connection(int port_number)
{
	int sockfd;
	struct sockaddr_in serv_addr;
	// create socket
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
	{
		perror("socket creation failed");
	}
	// set up address
	memset(&serv_addr, '0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port_number);
	if (inet_pton(AF_INET, LOCALHOST, &serv_addr.sin_addr) <= 0)
	{
		perror("inet_pton failed");
	}
	// connect
	if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
	{
		perror("connect failed");
	}
	return sockfd;
}

// FROM HOST SWITCH
void *greet_client_switch(void *arg)
{
	int socket_fd = *(int *)arg;
	// receive discovery packet
	BYTE buffer[TCP_BUFFER_SIZE];

	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}

	PACKET discovery_packet = bytes_to_packet(buffer);
	if (discovery_packet.mode != DISCOVER)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}

	// send offer packet
	PACKET offer_packet = new_packet(this_switch.global_ip.ip_address, zero_ip_address(), 0, OFFER, NULL);
	BYTE *offer_packet_bytes = packet_to_bytes(offer_packet);
	if (send(socket_fd, offer_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("send failed");
	}

	return NULL;
}

// FROM CLIENT SWITCH
void *greet_host_switch(void *arg)
{
	int port_number = *(int *)arg;

	int socket_fd = create_outgoing_connection(port_number);
	// send discovery packet

	PACKET discovery_packet = new_packet(zero_ip_address(), zero_ip_address(), 0, DISCOVER, NULL);
	BYTE *discovery_packet_bytes = packet_to_bytes(discovery_packet);

	// send discovery packet
	if (send(socket_fd, discovery_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("send failed");
	}

	// receive offer packet
	BYTE buffer[TCP_BUFFER_SIZE];
	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}

	PACKET offer_packet = bytes_to_packet(buffer);
	if (offer_packet.mode != OFFER)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}

	print_packet(offer_packet);

	all_connections.num_connections++;
	return NULL;
}

void listen_for_commands(void *arg)
{
	IP_ADDRESS n_higher = n_higher_ip_address(this_switch.global_ip.ip_address, 301);
	for (int i = 0; i < 4; i++)
	{
		printf("%d.", n_higher.octet[i]);
	}

	char command[COMMAND_BUFFER_SIZE];
	int port_number;
	while (fgets(command, sizeof(command), stdin) != NULL)
	{
		if (sscanf(command, "connect %d", &port_number) == 1)
		{
			pthread_t thread_id;
			pthread_create(&thread_id, NULL, greet_host_switch, &port_number);
		}
	}
}

void listen_for_switch_connections(void *arg)
{
	int socket_fd = *(int *)arg;
	// listen
	if (listen(socket_fd, 5) < 0)
	{
		perror("listen failed");
	}
	// continuously accept
	while (1)
	{
		int new_socket_fd;
		if ((new_socket_fd = accept(socket_fd, NULL, NULL)) < 0)
		{
			perror("accept failed");
		}
		pthread_t new_thread;
		pthread_create(&new_thread, NULL, greet_client_switch, &new_socket_fd);
	}
}

// typedef struct IP_ADDRESS_WITH_CIDR
// {
// 	IP_ADDRESS ip_address;
// 	unsigned char cidr;
// } IP_ADDRESS_WITH_CIDR;
// typedef struct IP_ADDRESS
// {
// 	unsigned char octet[4];
// } IP_ADDRESS;
// typedef struct SWITCH
// {
// 	SWITCH_TYPE type;
// 	IP_ADDRESS_WITH_CIDR local_ip;
// 	IP_ADDRESS_WITH_CIDR global_ip;
// 	int num_assigned_global_ips;
// 	int max_num_assigned_global_ips;
// 	int num_assigned_local_ips;
// 	int max_num_assigned_local_ips;
// 	unsigned short latitude;
// 	unsigned short longitude;
// } SWITCH;

// return an IP address n higher than the given IP address
IP_ADDRESS n_higher_ip_address(IP_ADDRESS ip_address, int n)
{
	unsigned long int ip_as_int = (ip_address.octet[0] << 24) +
								  (ip_address.octet[1] << 16) +
								  (ip_address.octet[2] << 8) +
								  ip_address.octet[3];
	ip_as_int += n;

	IP_ADDRESS new_ip;
	new_ip.octet[0] = (ip_as_int >> 24) & 0xFF;
	new_ip.octet[1] = (ip_as_int >> 16) & 0xFF;
	new_ip.octet[2] = (ip_as_int >> 8) & 0xFF;
	new_ip.octet[3] = ip_as_int & 0xFF;

	return new_ip;
}

// // The IP address allocated to the adapter/client switch by the host switch during the Greeting protocol is calculated in accordance with RFCs 1518 and 1519. The host switch will pick the smallest available IP to allocate to each incoming connection. For example, if an adapter were to connect to a mixed switch with the local IP 192.168.0.1/24 and that switch already had two other adapters connected to it, then this new adapter would be allocated the IP address 192.168.0.4 (as the first two adapters take 192.168.0.2 and 192.168.0.3 respec- tively). Similarly, if a global switch were to connect to a mixed switch with the global IP 130.102.72.01/24 and that switch already had seven other switches connected to it, then this new switch would be allocated the IP address 130.102.72.8. Both of these switches can support a maximum of 254 connections due to its CIDR of 24. If all connections are taken, then the switch will stop responding to incoming connections.
// IP_ADDRESS allocate_global_ip_address()
// {
// 	// This will keep track of the next IP to be assigned.
// 	static int ip_counter = ; // start at 2 because 0 is reserved for network address and 1 is reserved for gateway address

// 	// Check if the switch has reached its maximum number of assignments.
// 	if (this_switch.num_assigned_local_ips >= this_switch.max_num_assigned_local_ips)
// 	{
// 		// This switch is full. It cannot assign more IPs. Log the error or handle it appropriately.
// 		printf("Error: Maximum number of IP assignments reached for this switch. Cannot assign more IPs.\n");
// 		exit(1); // Or handle error appropriately
// 	}

// 	// Calculate the next IP to be assigned.
// 	IP_ADDRESS next_ip = this_switch.local_ip.ip_address;
// 	next_ip.octet[3] = ip_counter;

// 	// Increment the counter for the next assignment.
// 	ip_counter++;

// 	// Increase the count of assigned IPs.
// 	this_switch.num_assigned_local_ips++;

// 	return next_ip;
// }
