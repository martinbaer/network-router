#ifndef DISTANCE_RELAYING_H
#define DISTANCE_RELAYING_H

#include "packet.h"
#include "globals.h"

void inform_neighbour_switch_of_known_distances(NeighbourSwitch new_neighbour);

void relay_distance(KnownIpAddress subject, NeighbourSwitch informant);
NeighbourSwitch add_new_neighbour_switch(int socket_fd, IpAddress ip_address, int distance);
bool neighbour_switch_equals(NeighbourSwitch switch1, NeighbourSwitch switch2);
int calculate_distance(Coordinate location1, Coordinate location2);
Packet create_distance_packet(IpAddress source, IpAddress destination, IpAddress subject, int distance);

#endif
