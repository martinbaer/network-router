#ifndef CONNECT_SWITCH_H
#define CONNECT_SWITCH_H

#include "packet.h"

void *listen_for_commands(void *arg);
void *listen_for_switch_connections(void *arg);

#endif
