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

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = socket_type;
    hints.ai_flags = AI_PASSIVE;

    getaddrinfo(NULL, "0", &hints, &res);

    result.socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

    bind(result.socket, res->ai_addr, res->ai_addrlen);

    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    if (getsockname(result.socket, (struct sockaddr *)&sin, &len) == -1)
    {
        fprintf(stderr, "getsockname error\n");
        exit(1);
    }
    else
    {
        result.port = ntohs(sin.sin_port);
    }

    freeaddrinfo(res);

    return result;
}