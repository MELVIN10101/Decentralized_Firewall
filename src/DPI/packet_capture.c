#include <pcap.h>
#include "packet_capture.h"

void start_packet_capture(const char *interface, pcap_handler callback, void *user_data) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        return;
    }

    // Capture packets indefinitely
    pcap_loop(handle, 0, callback, (u_char *)user_data);

    pcap_close(handle);
}
