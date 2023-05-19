

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "invocation.h"
#include "open_port.h"
#include "packet.h"

int main(int argc, char *argv[])
{
    SWITCH sw = parse_command_line(argc, argv);

    if (sw.type == LOCAL || sw.type == MIXED)
    {
        // open UDP port
        PORT udp_port = open_port(SOCK_DGRAM);
        printf("%d\n", udp_port.port);
    }
    if (sw.type == GLOBAL || sw.type == MIXED)
    {
        // open TCP port
        PORT tcp_port = open_port(SOCK_STREAM);
        printf("%d\n", tcp_port.port);
    }

    return 0;
}