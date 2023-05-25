#ifndef PACKET_H
#define PACKET_H

#include <stdbool.h>

typedef unsigned char Byte;

typedef enum Mode
{
	DISCOVER = 0x01,
	OFFER = 0x02,
	REQUEST = 0x03,
	ACKNOWLEDGE = 0x04,
	DATA = 0x05,
	QUERY = 0x06,
	READY = 0x07,
	LOCATION = 0x08,
	DISTANCE = 0x09,
	MORE_FRAGMENTS = 0x0A,
	LAST_FRAGMENT = 0x0B,
} Mode;

typedef struct IpAddress
{
	unsigned char octet[4];
} IpAddress;

typedef struct Packet
{
	IpAddress source_ip;	  // 4 bytes
	IpAddress destination_ip; // 4 bytes
	unsigned int offset;	  // 3 bytes
	Mode mode;				  // 1 byte
	Byte *data;				  // rest of packet
} Packet;

typedef struct Coordinate
{
	unsigned short x;
	unsigned short y;
} Coordinate;

Coordinate bytes_to_xy_field(Byte *bytes);
Byte *xy_field_to_bytes(Coordinate xy_field);

Byte *packet_to_bytes(Packet packet);
Packet bytes_to_packet(Byte *bytes);

Byte *location_to_bytes(unsigned short latitude, unsigned short longitude);

Packet new_packet(IpAddress source_ip, IpAddress destination_ip, unsigned int offset, Mode mode, Byte *data);
Byte *ip_address_to_bytes(IpAddress ip_address);
IpAddress bytes_to_ip_address(Byte *bytes);
IpAddress zero_ip_address();

bool ip_address_equals(IpAddress ip_address1, IpAddress ip_address2);

void print_packet_as_bytes(Packet packet);
void print_packet(Packet packet);
void print_ip_address(IpAddress ip_address);

IpAddress new_ip_address(int octet1, int octet2, int octet3, int octet4);

#endif
