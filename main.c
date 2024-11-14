#include <stdio.h>
#include <pcap.h>
#include "packet_capture.h"
#include "packet_parser.h"

void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    ParsedPacket parsed_packet;
    parse_packet(packet, &parsed_packet);

    printf("| %-17s | %-17s | %-15s | %-15s | %-5u | %-5u |\n",
           parsed_packet.src_mac, parsed_packet.dest_mac,
           parsed_packet.src_ip, parsed_packet.dest_ip,
           parsed_packet.src_port, parsed_packet.dest_port);
}

int main() {
    const char *interface = "wlp0s20f3";  // Change as needed
    printf("| Source MAC         | Destination MAC    | Source IP       | Destination IP  | Src Port | Dst Port |\n");
    printf("|--------------------|--------------------|-----------------|-----------------|----------|----------|\n");
    start_packet_capture(interface, packet_handler, NULL);

    return 0;
}
