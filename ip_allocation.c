#include <stdio.h>

#include "ip_allocation.h"
#include "globals.h"

// return an IP address n higher than the given IP address
IpAddress n_higher_ip_address(IpAddress ip_address, int n)
{
	unsigned long int ip_as_int = (ip_address.octet[0] << 24) +
								  (ip_address.octet[1] << 16) +
								  (ip_address.octet[2] << 8) +
								  ip_address.octet[3];
	ip_as_int += n;

	IpAddress new_ip;
	new_ip.octet[0] = (ip_as_int >> 24) & 0xFF;
	new_ip.octet[1] = (ip_as_int >> 16) & 0xFF;
	new_ip.octet[2] = (ip_as_int >> 8) & 0xFF;
	new_ip.octet[3] = ip_as_int & 0xFF;

	return new_ip;
}

// The IP address allocated to the adapter/client switch by the host switch during the Greeting protocol is calculated in accordance with RFCs 1518 and 1519. The host switch will pick the smallest available IP to allocate to each incoming connection. For example, if an adapter were to connect to a mixed switch with the local IP 192.168.0.1/24 and that switch already had two other adapters connected to it, then this new adapter would be allocated the IP address 192.168.0.4 (as the first two adapters take 192.168.0.2 and 192.168.0.3 respec- tively). Similarly, if a global switch were to connect to a mixed switch with the global IP 130.102.72.01/24 and that switch already had seven other switches connected to it, then this new switch would be allocated the IP address 130.102.72.8. Both of these switches can support a maximum of 254 connections due to its CIDR of 24. If all connections are taken, then the switch will stop responding to incoming connections.
IpAddress allocate_global_ip_address()
{
	IpAddress ip_address = n_higher_ip_address(this_switch.global_ip.ip_address, ++this_switch.num_assigned_global_ips);
	return ip_address;
}

IpAddress allocate_local_ip_address()
{
	IpAddress ip_address = n_higher_ip_address(this_switch.local_ip.ip_address, ++this_switch.num_assigned_local_ips);
	return ip_address;
}
