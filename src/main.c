#include <stdio.h>
#include <stdlib.h>
#include "DPI/packet_capture.h"

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <network_interface>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *device = argv[1];
    printf("Initializing packet inspection module...\n");
    
    start_packet_capture(device);

    return EXIT_SUCCESS;
}
