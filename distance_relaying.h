#ifndef DISTANCE_RELAYING_H
#define DISTANCE_RELAYING_H

#include "packet.h"
#include "globals.h"

void relay_distance(KNOWN_SWITCH sender);
KNOWN_SWITCH add_new_known_switch(int socket_fd, IP_ADDRESS ip_address, int new_switch_distance);
bool known_switch_equals(KNOWN_SWITCH switch1, KNOWN_SWITCH switch2);
int calculate_distance(XY_FIELD location1, XY_FIELD location2);

#endif
