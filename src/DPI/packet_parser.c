#include "packet_parser.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdio.h>

void parse_packet(const u_char *packet, size_t packet_len, ParsedPacket *parsed_packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // Assuming Ethernet header size is 14 bytes

    // Extract IP addresses
    inet_ntop(AF_INET, &(ip_header->ip_src), parsed_packet->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), parsed_packet->dest_ip, INET_ADDRSTRLEN);

    // Determine protocol
    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        parsed_packet->src_port = ntohs(tcp_header->th_sport);
        parsed_packet->dest_port = ntohs(tcp_header->th_dport);
        strcpy(parsed_packet->protocol, "TCP");

        // Extract payload
        size_t ip_header_len = ip_header->ip_hl * 4;
        size_t tcp_header_len = tcp_header->th_off * 4;
        size_t payload_offset = 14 + ip_header_len + tcp_header_len;
        size_t payload_len = packet_len - payload_offset;

        if (payload_len > 0 && payload_len < MAX_PAYLOAD_SIZE) {
            memcpy(parsed_packet->payload, packet + payload_offset, payload_len);
            parsed_packet->payload_len = payload_len;
        } else {
            parsed_packet->payload_len = 0;
        }
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        parsed_packet->src_port = ntohs(udp_header->uh_sport);
        parsed_packet->dest_port = ntohs(udp_header->uh_dport);
        strcpy(parsed_packet->protocol, "UDP");

        // Extract payload
        size_t ip_header_len = ip_header->ip_hl * 4;
        size_t udp_header_len = sizeof(struct udphdr);
        size_t payload_offset = 14 + ip_header_len + udp_header_len;
        size_t payload_len = packet_len - payload_offset;

        if (payload_len > 0 && payload_len < MAX_PAYLOAD_SIZE) {
            memcpy(parsed_packet->payload, packet + payload_offset, payload_len);
            parsed_packet->payload_len = payload_len;
        } else {
            parsed_packet->payload_len = 0;
        }
    } else {
        strcpy(parsed_packet->protocol, "OTHER");
        parsed_packet->src_port = 0;
        parsed_packet->dest_port = 0;
        parsed_packet->payload_len = 0;
    }
}
