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
void greet_client_switch(int sock_fd)
{
}

void greet_host_switch(int sock_fd)
{
}

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

void *connect_to_client_switch(void *arg)
{
	int socket_fd = *(int *)arg;
	// receive discovery packet
	BYTE buffer[TCP_BUFFER_SIZE];

	if (recv(socket_fd, buffer, TCP_BUFFER_SIZE, 0) < 0)
	{
		perror("recv failed");
	}
	PACKET discovery_packet = bytes_to_packet(buffer);
	printf("Received discovery packet from client switch: ");
	print_packet(discovery_packet);
}

void *connect_to_host_switch(void *arg)
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

	all_connections.num_connections++;
	return NULL;
}

void listen_for_commands(void *arg)
{
	char command[COMMAND_BUFFER_SIZE];
	int port_number;
	while (fgets(command, sizeof(command), stdin) != NULL)
	{
		if (sscanf(command, "connect %d", &port_number) == 1)
		{
			pthread_t thread_id;
			pthread_create(&thread_id, NULL, connect_to_host_switch, &port_number);
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
		pthread_create(&new_thread, NULL, connect_to_client_switch, &new_socket_fd);
	}
}
