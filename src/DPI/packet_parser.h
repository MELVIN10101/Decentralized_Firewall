// src/DPI/packet_parser.h
#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <netinet/in.h>
#include <netinet/tcp.h>

typedef struct {
    char src_mac[18];
    char dest_mac[18];
    uint16_t ethertype;
    char src_ip[16];
    char dest_ip[16];
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t sequence_num;
    uint8_t tcp_flags;
    uint32_t ack_num;
    char app_name[256];  // Added to store the application name
    int direction; 
} ParsedPacket;

void parse_packet(const u_char *packet, ParsedPacket *parsed_packet);

#endif
