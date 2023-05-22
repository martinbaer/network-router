#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "open_port.h"

PORT open_port(int socket_type)
{
	PORT result;

	struct sockaddr_in server_addr;

	// Create the UDP socket
	result.socket = socket(AF_INET, socket_type, 0);
	if (result.socket < 0)
	{
		perror("Cannot open socket");
	}

	// Bind the socket to a specific port
	memset((char *)&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(0);

	if (bind(result.socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		perror("Cannot bind socket");
	}

	// Get the port number
	struct sockaddr_in sin;
	socklen_t sin_len = sizeof(sin);
	if (getsockname(result.socket, (struct sockaddr *)&sin, &sin_len) == -1)
	{
		perror("getsockname");
	}
	else
	{
		result.port = ntohs(sin.sin_port);
	}

	return result;
}
