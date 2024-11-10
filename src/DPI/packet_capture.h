#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

// Function to initialize and start packet capturing
void start_packet_capture(const char *device);

// Callback function to handle each captured packet
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

#endif
