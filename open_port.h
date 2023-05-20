#ifndef OPEN_PORT_H
#define OPEN_PORT_H

#include <sys/socket.h>
// ^ for SOCK_STREAM and SOCK_DGRAM

typedef struct PORT
{
    int port;
    int socket;
} PORT;

PORT open_port(int socket_type);

#endif
