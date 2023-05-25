#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globals.h"
#include "connect_switch.h"
#include "distance_relaying.h"
#include "data_forwarding.h"

#define COMMAND_BUFFER_SIZE 50
#define TCP_BUFFER_SIZE 1500

#define LOCALHOST "127.0.0.1"

IpAddress n_higher_ip_address(IpAddress ip_address, int n);
IpAddress allocate_global_ip_address();
IpAddress allocate_local_ip_address();

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

	// 4 bytes of 0
	Byte *empty_assigned_ip = malloc(4);
	memset(empty_assigned_ip, 0, 4);

	// receive discovery packet
	Byte buffer[TCP_BUFFER_SIZE];
	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}
	Packet discovery_packet = bytes_to_packet(buffer);
	if (discovery_packet.mode != DISCOVER)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}

	// send offer packet
	IpAddress assigned_ip = allocate_global_ip_address();
	Byte *assigned_ip_bytes = ip_address_to_bytes(assigned_ip);
	Packet offer_packet = new_packet(this_switch.global_ip.ip_address, zero_ip_address(), 0, OFFER, assigned_ip_bytes);
	Byte *offer_packet_bytes = packet_to_bytes(offer_packet);
	if (send(socket_fd, offer_packet_bytes, offer_packet.length, 0) < 0)
	{
		perror("send failed");
	}

	// receive request packet
	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}
	Packet request_packet = bytes_to_packet(buffer);
	if (request_packet.mode != REQUEST)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}

	// send acknowledgment packet
	Packet acknowledgment_packet = new_packet(this_switch.global_ip.ip_address, assigned_ip, 0, ACKNOWLEDGE, assigned_ip_bytes);
	Byte *acknowledgment_packet_bytes = packet_to_bytes(acknowledgment_packet);
	if (send(socket_fd, acknowledgment_packet_bytes, acknowledgment_packet.length, 0) < 0)
	{
		perror("send failed");
	}

	// receive location packet
	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}
	Packet client_location_packet = bytes_to_packet(buffer);
	if (client_location_packet.mode != LOCATION)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}
	Coordinate client_location = bytes_to_xy_field(client_location_packet.data);

	// add to list of known switches
	int new_switch_distance = calculate_distance(client_location, this_switch.location);
	NeighbourSwitch new_neighbour_switch = add_new_neighbour_switch(socket_fd, assigned_ip, new_switch_distance);

	// send location packet
	Byte *this_switch_location_bytes = xy_field_to_bytes(this_switch.location);
	Packet this_switch_location_packet = new_packet(this_switch.global_ip.ip_address, assigned_ip, 0, LOCATION, this_switch_location_bytes);
	Byte *this_switch_location_packet_bytes = packet_to_bytes(this_switch_location_packet);
	if (send(socket_fd, this_switch_location_packet_bytes, this_switch_location_packet.length, 0) < 0)
	{
		perror("send failed");
	}

	// relay distance
	KnownIpAddress *neighbour_known_ip_address = find_known_ip_address(new_neighbour_switch.ip_address);
	relay_distance(*neighbour_known_ip_address, new_neighbour_switch);

	// inform_neighbour_switch_of_known_distances(new_neighbour_switch);

	// if mixed switch, send distance to it's local ip
	if (this_switch.type == MIXED)
	{
		// Packet create_distance_packet(IpAddress sender, IpAddress receiver, IpAddress subject, int distance);

		// send distance to local ip
		Packet distance_packet = create_distance_packet(this_switch.global_ip.ip_address, assigned_ip, this_switch.local_ip.ip_address, new_switch_distance);
		// send
		Byte *distance_packet_bytes = packet_to_bytes(distance_packet);
		// print packet
		print_packet_as_bytes(distance_packet);
		if (send(socket_fd, distance_packet_bytes, distance_packet.length, 0) < 0)
		{
			perror("send failed");
		}
	}

	// listen and forward
	listen_and_forward(new_neighbour_switch);

	return NULL;
}

// FROM CLIENT SWITCH
void *greet_host_switch(void *arg)
{

	int port_number = *(int *)arg;

	int socket_fd = create_outgoing_connection(port_number);

	// 4 bytes of 0
	Byte *empty_assigned_ip = malloc(4);
	memset(empty_assigned_ip, 0, 4);

	// send discovery packet
	Packet discovery_packet = new_packet(zero_ip_address(), zero_ip_address(), 0, DISCOVER, empty_assigned_ip);
	Byte *discovery_packet_bytes = packet_to_bytes(discovery_packet);
	if (send(socket_fd, discovery_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("send failed");
	}

	// receive offer packet
	Byte buffer[TCP_BUFFER_SIZE];
	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}
	Packet offer_packet = bytes_to_packet(buffer);
	if (offer_packet.mode != OFFER)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}

	// send request packet
	Packet request_packet = new_packet(zero_ip_address(), offer_packet.source_ip, 0, REQUEST, offer_packet.data);
	Byte *request_packet_bytes = packet_to_bytes(request_packet);
	if (send(socket_fd, request_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("send failed");
	}

	// receive acknowledgment packet
	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}
	Packet acknowledgment_packet = bytes_to_packet(buffer);
	if (acknowledgment_packet.mode != ACKNOWLEDGE)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}

	// send location packet
	IpAddress my_assigned_ip = bytes_to_ip_address(acknowledgment_packet.data);
	Byte *this_switch_location_bytes = xy_field_to_bytes(this_switch.location);
	Packet location_packet = new_packet(my_assigned_ip, acknowledgment_packet.source_ip, 0, LOCATION, this_switch_location_bytes);
	Byte *location_packet_bytes = packet_to_bytes(location_packet);
	if (send(socket_fd, location_packet_bytes, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("send failed");
	}

	// receive location packet
	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}
	Packet host_location_packet = bytes_to_packet(buffer);
	if (host_location_packet.mode != LOCATION)
	{
		// end connection
		close(socket_fd);
		return NULL;
	}
	Coordinate host_location = bytes_to_xy_field(host_location_packet.data);

	// add to list of known switches
	int new_switch_distance = calculate_distance(host_location, this_switch.location);
	NeighbourSwitch new_neighbour_switch = add_new_neighbour_switch(socket_fd, acknowledgment_packet.source_ip, new_switch_distance);

	// relay distance
	KnownIpAddress *neighbour_known_ip_address = find_known_ip_address(new_neighbour_switch.ip_address);
	relay_distance(*neighbour_known_ip_address, new_neighbour_switch);

	// inform_neighbour_switch_of_known_distances(new_neighbour_switch);
	// listen and forward
	listen_and_forward(new_neighbour_switch);

	return NULL;
}

void *listen_for_commands(void *arg)
{

	char command[COMMAND_BUFFER_SIZE];
	int *port_number = malloc(sizeof(int));
	while (fgets(command, sizeof(command), stdin) != NULL)
	{
		if (sscanf(command, "connect %d", port_number) == 1)
		{
			pthread_t thread_id;
			pthread_create(&thread_id, NULL, greet_host_switch, port_number);
		}
	}
	return NULL;
}

void *listen_for_switch_connections(void *arg)
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
		int *new_socket_fd = malloc(sizeof(int));
		if ((*new_socket_fd = accept(socket_fd, NULL, NULL)) < 0)
		{
			perror("accept failed");
		}
		pthread_t new_thread;
		pthread_create(&new_thread, NULL, greet_client_switch, new_socket_fd);
	}
}

// typedef struct IP_ADDRESS_WITH_CIDR
// {
// 	IpAddress ip_address;
// 	unsigned char cidr;
// } IP_ADDRESS_WITH_CIDR;
// typedef struct IpAddress
// {
// 	unsigned char octet[4];
// } IpAddress;
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
