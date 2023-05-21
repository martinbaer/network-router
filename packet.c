#include <string.h>
#include <stdlib.h>
#include <stdio.h>

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
	int data_length = 0;
	if (packet.mode == DISCOVER || packet.mode == OFFER || packet.mode == REQUEST || packet.mode == ACKNOWLEDGE)
		data_length += 4;
	BYTE *result = malloc(12 + data_length);
	memcpy(result, ip_address_to_bytes(packet.source_ip), 4);
	memcpy(result + 4, ip_address_to_bytes(packet.destination_ip), 4);
	memcpy(result + 8, &packet.offset, 3);
	memcpy(result + 11, &packet.mode, 1);
	memcpy(result + 12, packet.data, data_length);
	return result;
}

// typedef struct IP_ADDRESS
// {
// 	unsigned char octet[4];
// } IP_ADDRESS;
IP_ADDRESS bytes_to_ip_address(BYTE *bytes)
{
	IP_ADDRESS result;
	memcpy(&result, bytes, 4);
	return result;
}

PACKET bytes_to_packet(BYTE *bytes)
{
	PACKET result;
	result.source_ip = bytes_to_ip_address(bytes);
	result.destination_ip = bytes_to_ip_address(bytes + 4);
	memcpy(&result.offset, bytes + 8, 3);
	memcpy(&result.mode, bytes + 11, 1);
	result.data = bytes + 12;
	return result;
}

PACKET new_packet(IP_ADDRESS source_ip, IP_ADDRESS destination_ip, unsigned int offset, MODE mode, BYTE *data)
{
	PACKET result;
	result.source_ip = source_ip;
	result.destination_ip = destination_ip;
	result.offset = offset;
	result.mode = mode;
	result.data = data;
	return result;
}

void print_packet_as_bytes(PACKET packet)
{
	// convert to bytes
	BYTE *discovery_packet_bytes = packet_to_bytes(packet);
	// get length
	int length = 12;
	if (packet.mode == DISCOVER || packet.mode == OFFER || packet.mode == REQUEST || packet.mode == ACKNOWLEDGE)
		length += 4;
	// print it
	printf("packet: \n");
	for (int i = 0; i < length; i++)
	{
		if (i % 4 == 0)
			printf("\n");
		printf("%02x ", discovery_packet_bytes[i]);
	}
	printf("\n");
	fflush(stdout);
}

void print_packet(PACKET packet)
{
	printf("packet: \n");
	printf("source ip: %d.%d.%d.%d\n", packet.source_ip.octet[0], packet.source_ip.octet[1], packet.source_ip.octet[2], packet.source_ip.octet[3]);
	printf("destination ip: %d.%d.%d.%d\n", packet.destination_ip.octet[0], packet.destination_ip.octet[1], packet.destination_ip.octet[2], packet.destination_ip.octet[3]);
	printf("offset: %d\n", packet.offset);
	printf("mode: %d\n", packet.mode);
	printf("data: %s\n", packet.data);
	fflush(stdout);
}
