#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "packet.h"

#define MAX_DATA_LENGTH 1488

// IP_ADDRESS source_ip;	   // 4 bytes
// IP_ADDRESS destination_ip; // 4 bytes
// unsigned int offset;	   // 3 bytes
// Mode mode;				   // 1 byte
// char *data;				   // rest of packet

// typedef unsigned char Byte;
// typedef struct Coordinate
// {
// 	unsigned short x;
// 	unsigned short y;
// } Coordinate;
// the bytes need to be in network byte order (big endian)

Coordinate bytes_to_xy_field(Byte *bytes)
{
	Coordinate xy_field;

	// Assuming bytes are in big endian (network byte order)
	xy_field.x = (bytes[0] << 8) | bytes[1];
	xy_field.y = (bytes[2] << 8) | bytes[3];

	return xy_field;
}

Byte *xy_field_to_bytes(Coordinate xy_field)
{
	Byte *bytes = (Byte *)malloc(sizeof(Byte) * 4);

	// Convert x and y from host byte order to network byte order
	bytes[0] = (xy_field.x >> 8) & 0xFF;
	bytes[1] = xy_field.x & 0xFF;
	bytes[2] = (xy_field.y >> 8) & 0xFF;
	bytes[3] = xy_field.y & 0xFF;

	return bytes;
}

IpAddress zero_ip_address()
{
	IpAddress result;
	memset(result.octet, 0, 4);
	return result;
}

Byte *ip_address_to_bytes(IpAddress ip_address)
{
	Byte *result = malloc(4);
	memcpy(result, &ip_address, 4);
	return result;
}

Byte *packet_to_bytes(Packet packet)
{
	int data_length = 0;
	if (packet.mode == DISCOVER || packet.mode == OFFER || packet.mode == REQUEST || packet.mode == ACKNOWLEDGE || packet.mode == LOCATION)
		data_length = 4;
	if (packet.mode == DISTANCE)
		data_length = 8;
	if (packet.mode == DATA)
		data_length = MAX_DATA_LENGTH;
	Byte *result = malloc(12 + data_length);
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
IpAddress bytes_to_ip_address(Byte *bytes)
{
	IpAddress result;
	memcpy(&result, bytes, 4);
	return result;
}

Packet bytes_to_packet(Byte *bytes)
{
	Packet result;
	result.source_ip = bytes_to_ip_address(bytes);
	result.destination_ip = bytes_to_ip_address(bytes + 4);
	memcpy(&result.offset, bytes + 8, 3);
	result.offset = result.offset & 0xFFFFFF;
	memcpy(&result.mode, bytes + 11, 1);
	result.offset = result.offset & 0xFF;
	result.data = bytes + 12;
	return result;
}

Packet new_packet(IpAddress source_ip, IpAddress destination_ip, unsigned int offset, Mode mode, Byte *data)
{
	Packet result;
	result.source_ip = source_ip;
	result.destination_ip = destination_ip;
	result.offset = offset;
	result.mode = mode;
	result.data = data;
	// get length
	result.length = 12;
	if (mode == DISCOVER || mode == OFFER || mode == REQUEST || mode == ACKNOWLEDGE || mode == LOCATION)
		result.length += 4;
	if (mode == DISTANCE)
		result.length += 8;
	return result;
}

bool ip_address_equals(IpAddress ip_address1, IpAddress ip_address2)
{
	for (int i = 0; i < 4; i++)
	{
		if (ip_address1.octet[i] != ip_address2.octet[i])
			return false;
	}
	return true;
}

void print_packet_as_bytes(Packet packet)
{
	// convert to bytes
	Byte *discovery_packet_bytes = packet_to_bytes(packet);
	// get length
	int length = 12;
	if (packet.mode == DISCOVER || packet.mode == OFFER || packet.mode == REQUEST || packet.mode == ACKNOWLEDGE || packet.mode == LOCATION)
		length += 4;
	if (packet.mode == DISTANCE)
		length += 8;
	// print it
	fprintf(stderr, "packet: \n");
	for (int i = 0; i < length; i++)
	{
		if (i % 4 == 0)
			fprintf(stderr, "\n");
		fprintf(stderr, "%02x ", discovery_packet_bytes[i]);
	}
	fprintf(stderr, "\n");
	fflush(stdout);
}

void print_packet(Packet packet)
{
	// printf("packet: \n");
	// printf("source ip: %d.%d.%d.%d\n", packet.source_ip.octet[0], packet.source_ip.octet[1], packet.source_ip.octet[2], packet.source_ip.octet[3]);
	// printf("destination ip: %d.%d.%d.%d\n", packet.destination_ip.octet[0], packet.destination_ip.octet[1], packet.destination_ip.octet[2], packet.destination_ip.octet[3]);
	// printf("offset: %d\n", packet.offset);
	// printf("mode: %d\n", packet.mode);
	// printf("data: %s\n", packet.data);
	// fflush(stdout);
	// stderr
	fprintf(stderr, "packet: \n");
	fprintf(stderr, "source ip: %d.%d.%d.%d\n", packet.source_ip.octet[0], packet.source_ip.octet[1], packet.source_ip.octet[2], packet.source_ip.octet[3]);
	fprintf(stderr, "destination ip: %d.%d.%d.%d\n", packet.destination_ip.octet[0], packet.destination_ip.octet[1], packet.destination_ip.octet[2], packet.destination_ip.octet[3]);
	fprintf(stderr, "offset: %d\n", packet.offset);
	fprintf(stderr, "mode: %d\n", packet.mode);
	fprintf(stderr, "data: %s\n", packet.data);
	fflush(stderr);
}

void print_ip_address(IpAddress ip_address)
{
	fprintf(stderr, "ip address: %d.%d.%d.%d\n", ip_address.octet[0], ip_address.octet[1], ip_address.octet[2], ip_address.octet[3]);
	fflush(stderr);
}

IpAddress new_ip_address(int octet1, int octet2, int octet3, int octet4)
{
	IpAddress result;
	result.octet[0] = octet1;
	result.octet[1] = octet2;
	result.octet[2] = octet3;
	result.octet[3] = octet4;
	return result;
}
