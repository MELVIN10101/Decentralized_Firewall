#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>

#define MAX_PAYLOAD_SIZE 1500

typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    uint16_t src_port;
    uint16_t dest_port;
    char protocol[16];
    char payload[MAX_PAYLOAD_SIZE];
    size_t payload_len;
} ParsedPacket;

void parse_packet(const u_char *packet, size_t packet_len, ParsedPacket *parsed_packet);

#endif
