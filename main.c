#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "packet_parser.h"
#include "packet_capture.h"
#include "traffic_classification.h"


void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    // Initialize parsed packet structure
    ParsedPacket parsed_packet;
    parse_packet(packet, header->caplen, &parsed_packet);
    const char *traffic_type = print_traffic_classification(parsed_packet.src_port, parsed_packet.dest_port);
    // Print parsed packet details
    printf("\n================= PACKET INFO =================\n");
    printf("Source IP: %s\n", parsed_packet.src_ip);
    printf("Destination IP: %s\n", parsed_packet.dest_ip);
    printf("Source Port: %u\n", parsed_packet.src_port);
    printf("Destination Port: %u\n", parsed_packet.dest_port);
    printf("Protocol: %s\n", parsed_packet.protocol);
    printf("Traffic Type: %s\n", traffic_type);
    printf("Payload Length: %zu bytes\n", parsed_packet.payload_len);

    // Print payload if present
    if (parsed_packet.payload_len > 0) {
        printf("Payload:\n");
        for (size_t i = 0; i < parsed_packet.payload_len; i++) {
            printf("%c", parsed_packet.payload[i]);
        }
        printf("\n");
    } else {
        printf("No payload data available.\n");
    }

    // Print raw packet data
    printf("\nRaw Packet Data (%u bytes):\n", header->caplen);
    for (size_t i = 0; i < header->caplen; i++) {
        printf("%02x ", packet[i]);

        // Format output for readability
        if ((i + 1) % 16 == 0) {
            printf("\n");
        } else if ((i + 1) % 8 == 0) {
            printf("  ");
        }
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *interface = argv[1];
    printf("Starting packet capture on interface: %s\n", interface);

    // Start packet capture
    start_packet_capture(interface, packet_handler, NULL);

    return 0;
}
