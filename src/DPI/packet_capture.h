#ifndef PACKET_CAPTURE_H
#define PACKET_CAPTURE_H

#include <pcap.h>

void start_packet_capture(const char *interface, pcap_handler callback, void *user_data);

#endif // PACKET_CAPTURE_H
