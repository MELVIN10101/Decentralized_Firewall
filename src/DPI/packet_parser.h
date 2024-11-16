#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdint.h>
#include <arpa/inet.h>   // For INET_ADDRSTRLEN
#include <pcap.h>        // For u_char type

// 10-tuple structure for processed packet data
typedef struct {
    char src_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];
    char src_mac[18];
    char dest_mac[18];
    uint16_t src_port;
    uint16_t dest_port;
    char protocol_name[10];
    uint8_t protocol;
    int direction; // 1 for incoming, 0 for outgoing
    char app_name[256]; // Associated application (optional)
    char payload[MAX_PAYLOAD_SIZE]; // Add payload field
    size_t payload_len; 
} ParsedPacket;

// Function to parse a raw packet into ParsedPacket
void parse_packet(const u_char *packet, ParsedPacket *parsed_packet);

#endif
