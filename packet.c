#include <string.h>
#include <stdlib.h>

#include "packet.h"

// IP_ADDRESS source_ip;	   // 4 bytes
// IP_ADDRESS destination_ip; // 4 bytes
// unsigned int offset;	   // 3 bytes
// MODE mode;				   // 1 byte
// char *data;				   // rest of packet

IP_ADDRESS zero_ip_address()
{
	IP_ADDRESS result;
	memset(result.octet, 0, 4);
	return result;
}

BYTE *ip_address_to_bytes(IP_ADDRESS ip_address)
{
	BYTE *result = malloc(4);
	memcpy(result, &ip_address, 4);
	return result;
}

BYTE *packet_to_bytes(PACKET packet)
{
	BYTE *result = malloc(12 + packet.offset);
	// TODO: i think some cases the offset will be 0 but the data will be non-null
	memcpy(result, ip_address_to_bytes(packet.source_ip), 4);
	memcpy(result + 4, ip_address_to_bytes(packet.destination_ip), 4);
	memcpy(result + 8, &packet.offset, 3);
	memcpy(result + 11, &packet.mode, 1);
	memcpy(result + 12, packet.data, packet.offset);
	return result;
}

PACKET new_packet(IP_ADDRESS source_ip, IP_ADDRESS destination_ip, unsigned int offset, MODE mode, char *data)
{
	PACKET result;
	result.source_ip = source_ip;
	result.destination_ip = destination_ip;
	result.offset = offset;
	result.mode = mode;
	result.data = data;
	return result;
}

void print_packet(PACKET packet)
{
	// convert to bytes
	BYTE *discovery_packet_bytes = packet_to_bytes(packet);
	// print it
	printf("packet: \n");
	for (int i = 0; i < 12; i++)
	{
		if (i % 4 == 0)
			printf("\n");
		printf("%02x ", discovery_packet_bytes[i]);
	}
	printf("\n");
}
