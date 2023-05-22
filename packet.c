#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "packet.h"

#define MAX_DATA_LENGTH 1488

// IP_ADDRESS source_ip;	   // 4 bytes
// IP_ADDRESS destination_ip; // 4 bytes
// unsigned int offset;	   // 3 bytes
// MODE mode;				   // 1 byte
// char *data;				   // rest of packet

// typedef unsigned char BYTE;
// typedef struct XY_FIELD
// {
// 	unsigned short x;
// 	unsigned short y;
// } XY_FIELD;
// the bytes need to be in network byte order (big endian)

XY_FIELD bytes_to_xy_field(BYTE *bytes)
{
	XY_FIELD xy_field;

	// Assuming bytes are in big endian (network byte order)
	xy_field.x = (bytes[0] << 8) | bytes[1];
	xy_field.y = (bytes[2] << 8) | bytes[3];

	return xy_field;
}

BYTE *xy_field_to_bytes(XY_FIELD xy_field)
{
	BYTE *bytes = (BYTE *)malloc(sizeof(BYTE) * 4);

	// Convert x and y from host byte order to network byte order
	bytes[0] = (xy_field.x >> 8) & 0xFF;
	bytes[1] = xy_field.x & 0xFF;
	bytes[2] = (xy_field.y >> 8) & 0xFF;
	bytes[3] = xy_field.y & 0xFF;

	return bytes;
}

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
	if (packet.mode == DISCOVER || packet.mode == OFFER || packet.mode == REQUEST || packet.mode == ACKNOWLEDGE || packet.mode == LOCATION)
		data_length = 4;
	if (packet.mode == DISTANCE)
		data_length = 8;
	if (packet.mode == DATA)
		data_length = MAX_DATA_LENGTH;
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

bool ip_address_equals(IP_ADDRESS ip_address1, IP_ADDRESS ip_address2)
{
	for (int i = 0; i < 4; i++)
	{
		if (ip_address1.octet[i] != ip_address2.octet[i])
			return false;
	}
	return true;
}

void print_packet_as_bytes(PACKET packet)
{
	// convert to bytes
	BYTE *discovery_packet_bytes = packet_to_bytes(packet);
	// get length
	int length = 12;
	if (packet.mode == DISCOVER || packet.mode == OFFER || packet.mode == REQUEST || packet.mode == ACKNOWLEDGE || packet.mode == LOCATION)
		length += 4;
	if (packet.mode == DISTANCE)
		length += 8;
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
