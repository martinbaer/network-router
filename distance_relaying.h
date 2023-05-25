#ifndef DISTANCE_RELAYING_H
#define DISTANCE_RELAYING_H

#include "packet.h"
#include "globals.h"

void inform_switch_of_known_distances(NeighbourSwitch known_switch);

void relay_distance(NeighbourSwitch subject, NeighbourSwitch informant);
NeighbourSwitch add_new_known_switch(int socket_fd, IpAddress ip_address, int new_switch_distance, IpAddress next_hop, int next_hop_socket_fd, IpAddress distance_informant_ip_address);
bool known_switch_equals(NeighbourSwitch switch1, NeighbourSwitch switch2);
int calculate_distance(Coordinate location1, Coordinate location2);

#endif
