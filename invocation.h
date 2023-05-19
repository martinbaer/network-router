#ifndef INVOCATION_H
#define INVOCATION_H

typedef enum SWITCH_TYPE
{
    LOCAL,
    GLOBAL,
    MIXED
} SWITCH_TYPE;

typedef struct IP_ADDRESS_WITH_CIDR
{
    unsigned char octet[4];
    unsigned char cidr;
} IP_ADDRESS_WITH_CIDR;

typedef struct SWITCH
{
    SWITCH_TYPE type;
    IP_ADDRESS_WITH_CIDR local_ip;
    IP_ADDRESS_WITH_CIDR global_ip;
    unsigned short latitude;
    unsigned short longitude;
} SWITCH;

SWITCH parse_command_line(int argc, char *argv[]);

#endif