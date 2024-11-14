// src/DPI/packet_parser.c

#include "packet_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

// Function to get the application name associated with the given PID
char *get_app_name(pid_t pid) {
    static char app_name[256];
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *fp = fopen(path, "r");

    if (fp != NULL) {
        if (fgets(app_name, sizeof(app_name), fp) != NULL) {
            fclose(fp);
            return app_name;
        }
        fclose(fp);
    }
    return "Unknown";
}

// Function to parse a packet
void parse_packet(const u_char *packet, ParsedPacket *parsed_packet) {
    struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));  // IP header
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));  // TCP header
    struct ether_header *eth_header = (struct ether_header *)packet;  // Ethernet header

    // Extract IP addresses
    inet_ntop(AF_INET, &(ip_header->ip_src), parsed_packet->src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), parsed_packet->dest_ip, INET_ADDRSTRLEN);

    // Extract MAC addresses
    snprintf(parsed_packet->src_mac, sizeof(parsed_packet->src_mac), "%s", ether_ntoa((struct ether_addr *)eth_header->ether_shost));
    snprintf(parsed_packet->dest_mac, sizeof(parsed_packet->dest_mac), "%s", ether_ntoa((struct ether_addr *)eth_header->ether_dhost));

    // Extract TCP details
    parsed_packet->src_port = ntohs(tcp_header->th_sport);
    parsed_packet->dest_port = ntohs(tcp_header->th_dport);
    parsed_packet->sequence_num = ntohl(tcp_header->th_seq);
    parsed_packet->ack_num = ntohl(tcp_header->th_ack);

    // Determine direction (1 for incoming, 0 for outgoing)
    if (strcmp(parsed_packet->src_ip, "your_local_ip_here") == 0) {
        parsed_packet->direction = 0;  // Outgoing
    } else if (strcmp(parsed_packet->dest_ip, "your_local_ip_here") == 0) {
        parsed_packet->direction = 1;  // Incoming
    } else {
        parsed_packet->direction = -1; // Unknown direction
    }

    // Get the application name associated with the source port (simplified)
    // This is an approximation. You would need to map port numbers to application names in a real case.
    pid_t pid = getpid();  // Replace with actual PID from netstat/ss if possible
    snprintf(parsed_packet->app_name, sizeof(parsed_packet->app_name), "%s", get_app_name(pid));
}
