#include "packet_parser.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <string.h>
#include <stdio.h>

extern char local_ip[INET_ADDRSTRLEN]; // Define in main.c or as a global

void parse_packet(const u_char *packet, ParsedPacket *parsed_packet) {
    struct ether_header *eth_header = (struct ether_header *)packet;
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));

    // Extract IP addresses
    inet_ntop(AF_INET, &(ip_header->ip_src), parsed_packet->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), parsed_packet->dest_ip, INET_ADDRSTRLEN);

    // Extract MAC addresses
    snprintf(parsed_packet->src_mac, sizeof(parsed_packet->src_mac), "%s", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    snprintf(parsed_packet->dest_mac, sizeof(parsed_packet->dest_mac), "%s", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // Extract protocol details
    parsed_packet->protocol = ip_header->ip_p;
    if (parsed_packet->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
        parsed_packet->src_port = ntohs(tcp_header->source);
        parsed_packet->dest_port = ntohs(tcp_header->dest);
        strcpy(parsed_packet->protocol_name, "TCP");
    } else if (parsed_packet->protocol == IPPROTO_UDP) {
        struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4));
        parsed_packet->src_port = ntohs(udp_header->source);
        parsed_packet->dest_port = ntohs(udp_header->dest);
        strcpy(parsed_packet->protocol_name, "UDP");
    } else {
        strcpy(parsed_packet->protocol_name, "Other");
        parsed_packet->src_port = 0;
        parsed_packet->dest_port = 0;
    }

    // Determine direction
    if (strcmp(parsed_packet->src_ip, local_ip) == 0) {
        parsed_packet->direction = 0; // Outgoing
    } else if (strcmp(parsed_packet->dest_ip, local_ip) == 0) {
        parsed_packet->direction = 1; // Incoming
    } else {
        parsed_packet->direction = -1; // Unknown
    }

    // Application name (optional implementation)
    snprintf(parsed_packet->app_name, sizeof(parsed_packet->app_name), "Unknown");
}
