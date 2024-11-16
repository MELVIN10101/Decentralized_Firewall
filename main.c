#include <stdio.h>
#include <pcap.h>
#include "packet_capture.h"
#include "packet_parser.h"
char local_ip[INET_ADDRSTRLEN];
// Callback function for handling captured packets
void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet) {
    ParsedPacket parsed_packet;

    // Parse the captured packet
    parse_packet(packet, &parsed_packet);

    // Print the parsed packet data as a table row
    printf(
        "| %-15s | %-15s | %-17s | %-17s | %-5u | %-5u | %-7s | %-4d |\n",
        parsed_packet.src_ip,
        parsed_packet.dest_ip,
        parsed_packet.src_mac,
        parsed_packet.dest_mac,
        parsed_packet.src_port,
        parsed_packet.dest_port,
        parsed_packet.protocol_name,
        parsed_packet.direction
        //parsed_packet.app_name
    );
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    // Print table header
    printf(
        "+-----------------+-----------------+-------------------+-------------------+-------+-------+---------+------+\n"
        "| Source IP       | Destination IP  | Source MAC        | Destination MAC   | SPort | DPort | Protocol | Dir |\n"
        "+-----------------+-----------------+-------------------+-------------------+-------+-------+---------+------+\n"
    );

    // Start capturing packets
    start_packet_capture(argv[1], packet_handler, NULL);

    // Print table footer
    printf(
        "+-----------------+-----------------+-------------------+-------------------+-------+-------+---------+------+------------+\n"
    );

    return 0;
}
