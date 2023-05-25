#ifndef IP_ALLOCATION_H
#define IP_ALLOCATION_H

#include "packet.h"
IpAddress allocate_global_ip_address();
IpAddress allocate_local_ip_address();

#endif
