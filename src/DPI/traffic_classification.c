#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Define traffic types
typedef enum {
    HTTP,HTTPS,FTP,DNS,SSH,TELNET,SMTP,POP3,IMAP,SNMP,TFTP,NTP,RDP,MYSQL,POSTGRESQL,MONGODB,SMB,KERBEROS,LDAP,REDIS,MQTT,COAP,SIP,RTSP,BGP,BITTORRENT,IRC,OPENVPN,IPSEC,MINECRAFT,UNKNOWN
} TrafficType;

// Function to classify traffic based on port
TrafficType classify_traffic(uint16_t port) {
    switch (port) {
        case 80: return HTTP;
        case 443: return HTTPS;
        case 21: case 20: return FTP;
        case 53: return DNS;
        case 22: return SSH;
        case 23: return TELNET;
        case 25: case 587: return SMTP;
        case 110: case 995: return POP3;
        case 143: case 993: return IMAP;
        case 161: case 162: return SNMP;
        case 69: return TFTP;
        case 123: return NTP;
        case 3389: return RDP;
        case 3306: return MYSQL;
        case 5432: return POSTGRESQL;
        case 27017: return MONGODB;
        case 445: case 137: case 138: case 139: return SMB;
        case 88: return KERBEROS;
        case 389: case 636: return LDAP;
        case 6379: return REDIS;
        case 1883: case 8883: return MQTT;
        case 5683: return COAP;
        case 5060: case 5061: return SIP;
        case 554: return RTSP;
        case 179: return BGP;
        case 6881 ... 6889: return BITTORRENT;
        case 6660 ... 6669: case 194: return IRC;
        case 1194: return OPENVPN;
        case 500: case 4500: return IPSEC;
        case 25565: return MINECRAFT;
        default: return UNKNOWN;
    }
}

// Function to convert traffic type to string
const char* traffic_type_to_string(TrafficType type) {
    switch (type) {
        case HTTP: return "HTTP";
        case HTTPS: return "HTTPS";
        case FTP: return "FTP";
        case DNS: return "DNS";
        case SSH: return "SSH";
        case TELNET: return "Telnet";
        case SMTP: return "SMTP";
        case POP3: return "POP3";
        case IMAP: return "IMAP";
        case SNMP: return "SNMP";
        case TFTP: return "TFTP";
        case NTP: return "NTP";
        case RDP: return "RDP";
        case MYSQL: return "MySQL";
        case POSTGRESQL: return "PostgreSQL";
        case MONGODB: return "MongoDB";
        case SMB: return "SMB";
        case KERBEROS: return "Kerberos";
        case LDAP: return "LDAP";
        case REDIS: return "Redis";
        case MQTT: return "MQTT";
        case COAP: return "CoAP";
        case SIP: return "SIP";
        case RTSP: return "RTSP";
        case BGP: return "BGP";
        case BITTORRENT: return "BitTorrent";
        case IRC: return "IRC";
        case OPENVPN: return "OpenVPN";
        case IPSEC: return "IPSec";
        case MINECRAFT: return "Minecraft";
        default: return "Unknown Traffic";
    }
}

// Function to classify and print traffic
// Function to classify and return a string representation of traffic
const char *print_traffic_classification(uint16_t source_port, uint16_t destination_port) {
    TrafficType source_class = classify_traffic(source_port);
    TrafficType dest_class = classify_traffic(destination_port);

    // Return the more specific classification if available
    if (source_class != UNKNOWN) {
        return traffic_type_to_string(source_class);
    } else if (dest_class != UNKNOWN) {
        return traffic_type_to_string(dest_class);
    } else {
        return "Unknown Traffic";
    }
}

