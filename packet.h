#ifndef PACKET_H
#define PACKET_H

typedef unsigned char BYTE;

typedef enum MODE
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
} MODE;

typedef struct IP_ADDRESS
{
	unsigned char octet[4];
} IP_ADDRESS;

typedef struct PACKET
{
	IP_ADDRESS source_ip;	   // 4 bytes
	IP_ADDRESS destination_ip; // 4 bytes
	unsigned int offset;	   // 3 bytes
	MODE mode;				   // 1 byte
	BYTE *data;				   // rest of packet
} PACKET;

BYTE *packet_to_bytes(PACKET packet);
PACKET bytes_to_packet(BYTE *bytes);

PACKET new_packet(IP_ADDRESS source_ip, IP_ADDRESS destination_ip, unsigned int offset, MODE mode, BYTE *data);
BYTE *ip_address_to_bytes(IP_ADDRESS ip_address);
IP_ADDRESS zero_ip_address();

void print_packet_as_bytes(PACKET packet);
void print_packet(PACKET packet);
void print_bytes(BYTE *bytes);

#endif
