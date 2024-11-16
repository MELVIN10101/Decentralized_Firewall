#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>

// Function to get application name from a port
char *get_app_name(unsigned short port) {
    static char app_name[256];
    char cmd[256];
    FILE *fp;

    snprintf(cmd, sizeof(cmd), "lsof -i:%hu -sTCP:LISTEN -n -P | awk 'NR==2 {print $1}'", port);
    fp = popen(cmd, "r");
    if (fp) {
        if (fgets(app_name, sizeof(app_name), fp) != NULL) {
            // Remove newline character
            app_name[strcspn(app_name, "\n")] = '\0';
        }
        pclose(fp);
    }
    return strlen(app_name) > 0 ? app_name : "Unknown";
}

// Packet handler callback
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ip *ip_header = (struct ip *)(packet + 14); // IP header starts after Ethernet
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

    // Extract source and destination IP
    inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Extract protocol type
    const char *protocol = "Unknown";
    unsigned short src_port = 0, dest_port = 0;
    char app_name[256] = "Unknown";

    if (ip_header->ip_p == IPPROTO_TCP) {
        protocol = "TCP";
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        src_port = ntohs(tcp_header->source);
        dest_port = ntohs(tcp_header->dest);
        strncpy(app_name, get_app_name(src_port), sizeof(app_name));
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        protocol = "UDP";
        struct udphdr *udp_header = (struct udphdr *)(packet + 14 + (ip_header->ip_hl * 4));
        src_port = ntohs(udp_header->source);
        dest_port = ntohs(udp_header->dest);
        strncpy(app_name, get_app_name(src_port), sizeof(app_name));
    }

    // Print captured packet information in a tabular format
    printf("%-15s | %-15s | %-8u | %-8u | %-6s | %-10s\n", src_ip, dest_ip, src_port, dest_port, protocol, app_name);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program filter;
    char filter_exp[] = "ip";
    bpf_u_int32 net, mask;

    // Find a device
    pcap_if_t *alldevs, *device;
char *dev = NULL;

// Get the list of available devices
if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
    return 1;
}

// Use the first device in the list
device = alldevs;
if (device != NULL) {
    dev = device->name;
    printf("Using device: %s\n", dev);
} else {
    fprintf(stderr, "No devices found for packet capture.\n");
    return 1;
}

// Free the list of devices
pcap_freealldevs(alldevs);

    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    // Get network address and mask
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    // Open the device for sniffing
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }

    // Compile and set the filter
    if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }

    // Print header
    printf("Source IP       | Dest IP         | Src Port | Dst Port | Proto  | Application\n");
    printf("--------------------------------------------------------------------------------------\n");

    // Capture packets
    pcap_loop(handle, 0, packet_handler, NULL);

    // Close the handle
    pcap_close(handle);
    return 0;
}
