#include "packet_capture.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include<sys/types.h>

// Packet handler for debugging
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    printf("\n--- Packet Captured ---\n");
    printf("Packet length: %d bytes\n", header->len);
    printf("Captured length: %d bytes\n", header->caplen);
    printf("Timestamp: %ld.%06ld\n", header->ts.tv_sec, header->ts.tv_usec);

    // Print the raw packet data for initial testing (limit to 64 bytes)
    printf("Packet data:\n");
    for (int i = 0; i < header->caplen && i < 64; i++) {
        printf("%02x ", packet[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    printf("\n--- End of Packet ---\n");
}

void start_packet_capture(const char *device) {
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(device, BUFSIZ, 1, 1000, error_buffer);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
        exit(EXIT_FAILURE);
    }

    printf("Starting packet capture on device %s...\n", device);
    pcap_loop(handle, 0, packet_handler, NULL);  // Infinite loop to capture packets

    pcap_close(handle);
    printf("Packet capture complete.\n");
}
