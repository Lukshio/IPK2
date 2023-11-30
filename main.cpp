/**
 * @file main.cpp
 * @author Lukáš Ježek <xjezek19@stud.fit.vutbr.cz>
 *
 *   [1] [Zadání projektu](https://git.fit.vutbr.cz/NESFIT/IPK-Projekty/src/branch/master/Project%202/zeta)
 *   [2] [TCPReplay](https://tcpreplay.appneta.com)
 *   [3] [PCAP](https://www.tcpdump.org/manpages/pcap.3pcap.html)
 *   [4] [MLD wiki](https://en.wikipedia.org/wiki/Multicast_Listener_Discovery)
 *   [5] [NDP wiki](https://cs.wikipedia.org/wiki/Neighbor_Discovery_Protocol)
 *   [6] [ICMPv6 wiki](https://cs.wikipedia.org/wiki/ICMPv6)
*/

#include <iostream>
#include <cstdio>
#include <cstring>
#include <getopt.h>
#include <string>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netdb.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <netinet/if_ether.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>


using namespace std;


/**
 * Print usage of script
 */
void usage() {
    cout
            << "Usage: [-i interface | --interface interface] -p port [--tcp|-t] [--udp|-u] [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] -n num"
            << endl;
}

/**
 * Helper function for get realtime timestamp
 * @return
 */
string getTimestamp() {
    // get timestamp
    chrono::system_clock::time_point now = chrono::system_clock::now();
    time_t timestamp = chrono::system_clock::to_time_t(now);

    // convert timestamp
    stringstream stream;
    stream << std::put_time(std::localtime(&timestamp), "%FT%T%z");
    std::string iso_timestamp = stream.str();
    return iso_timestamp;
}

/**
 * Prints tcp and udp ports
 * @param protocol
 * @param ipHeader
 * @param packet
 */
void printTcpUdpPorts(unsigned int protocol, struct iphdr *ipHeader, const u_char *packet) {
    string dstPort;
    string srcPort;
    if (protocol == 6) {
        auto *tcpHeader = (struct tcphdr *) (packet + sizeof(struct ethhdr) + (ipHeader->ihl * 4));
        srcPort = to_string(ntohs(tcpHeader->source));
        dstPort = to_string(ntohs(tcpHeader->dest));
    }
    if (protocol == 17) {
        auto *udpHeader = (struct udphdr *) (packet + sizeof(struct ethhdr) + (ipHeader->ihl * 4));
        srcPort = to_string(ntohs(udpHeader->source));
        dstPort = to_string(ntohs(udpHeader->dest));
    }
    cout << "src port: " << srcPort << endl;
    cout << "dst port: " << dstPort << endl << endl;
}

/**
 * Function prints all available interfaces
 */
void printInterfaces() {
    char errbuff[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces;
    if (pcap_findalldevs(&interfaces, errbuff) == -1) {
        cerr << "Error finding interfaces: " << errbuff << endl;
        exit(EXIT_FAILURE);
    }
    cout << "Interfaces:" << endl;
    for (pcap_if_t *i = interfaces; i != nullptr; i = i->next) {
        cout << "    " << i->name;
        if (i->description) {
            cout << " (" << i->description << ")";
        }
        cout << endl;
    }
    pcap_freealldevs(interfaces);
}

/**
 * Helper function for printPacketData
 * @param dataChar
 * @param len
 * @param offset
 */
void printLine(const u_char *dataChar, int len, int offset) {
    int gap;
    const u_char *ch;

    // print first col = offset
    printf("0x%04x   ", offset);

    // print hexa
    ch = dataChar;
    for (int i = 0; i < len; i++) {
        printf("%02x ", *ch);
        ch++;
    }

    // divider between hexa and ascii print
    if (len < 16) {
        gap = 16 - len;
        for (int i = 0; i < gap; i++) {
            cout << "   ";
        }
    }
    cout << "   ";

    // print ascii
    ch = dataChar;
    for (int i = 0; i < len; i++) {
        (isprint(*ch)) ? cout << *ch : cout << '.';
        ch++;
    }
    cout << endl;
}

/**
 * Print formatted data using helper function printLine
 * @param data
 * @param dataLen
 */
void printPacketData(const u_char *data, int dataLen) {
    int lenRem = dataLen;           // remaining len
    int lineLen;                    // len of printed line
    int offset = 0;
    const u_char *dataChar = data;

    // cout << endl;
    if (dataLen <= 0) return;
    if (dataLen <= 16) {
        printLine(dataChar, dataLen, offset);
        return;
    }

    while (true) {
        lineLen = 16 % lenRem;          // get new len
        printLine(dataChar, lineLen, offset);
        lenRem = lenRem - lineLen;      // update remaining
        dataChar = dataChar + lineLen;  // update pointer
        offset = offset + 16;           // update offset
        // if less than 16, no more lines needed
        if (lenRem <= 16) {
            printLine(dataChar, lenRem, offset);
            break;
        }
    }
}

/**
 * Function for printing all informations of packet
 * @param ethernetHeader
 * @param packet
 * @param ipHeader
 * @param header
 */
void printPacket(struct ether_header *ethernetHeader, const u_char *packet, struct iphdr *ipHeader,
                 const struct pcap_pkthdr *header) {
    //print
    cout << "timestamp: " << getTimestamp() << endl;
    printf("src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernetHeader->ether_shost[0], ethernetHeader->ether_shost[1],
           ethernetHeader->ether_shost[2], ethernetHeader->ether_shost[3], ethernetHeader->ether_shost[4],
           ethernetHeader->ether_shost[5]);
    printf("dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", ethernetHeader->ether_dhost[0], ethernetHeader->ether_dhost[1],
           ethernetHeader->ether_dhost[2], ethernetHeader->ether_dhost[3], ethernetHeader->ether_dhost[4],
           ethernetHeader->ether_dhost[5]);
    cout << "frame length: " << header->len << " bytes" << endl;

    // Diferent implementation for ARP,IPv4,IPv6
    if (ethernetHeader->ether_type == htons(ETH_P_IP) || ethernetHeader->ether_type == htons(ETH_P_ARP)) {
        char srcIP[INET_ADDRSTRLEN];
        char dstIP[INET_ADDRSTRLEN];

        if (ethernetHeader->ether_type == htons(ETH_P_IP)) {
            inet_ntop(AF_INET, &(ipHeader->saddr), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(ipHeader->daddr), dstIP, INET_ADDRSTRLEN);
        } else if (ethernetHeader->ether_type == htons(ETH_P_ARP)) {
            auto *arpPacket = (struct ether_arp *) (packet + sizeof(struct ethhdr));

            inet_ntop(AF_INET, &(arpPacket->arp_spa), srcIP, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(arpPacket->arp_tpa), dstIP, INET_ADDRSTRLEN);
        }

        cout << "src IP: " << srcIP << endl;
        cout << "dst IP: " << dstIP << endl;
    } else if (ethernetHeader->ether_type == htons(ETH_P_IPV6)) {
        char srcIP[INET6_ADDRSTRLEN];
        char dstIP[INET6_ADDRSTRLEN];

        struct ip6_hdr *ipv6Header;
        ipv6Header = (struct ip6_hdr *) (packet + sizeof(struct ether_header));

        inet_ntop(AF_INET6, &(ipv6Header->ip6_src), srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ipv6Header->ip6_dst), dstIP, INET6_ADDRSTRLEN);

        cout << "src IP: " << srcIP << endl;
        cout << "dst IP: " << dstIP << endl;
    }
}

/**
 * Main pcap loop function for parsing packet
 * @param args
 * @param header
 * @param packet
 */
void parsePacket(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    // get eth header
    struct ether_header *ethernetHeader;
    ethernetHeader = (struct ether_header *) packet;

    // get IP header info
    struct iphdr *ipHeader;
    ipHeader = (struct iphdr *) (packet + sizeof(struct ethhdr));
    auto protocol = (unsigned int) ipHeader->protocol;

    printPacket(ethernetHeader, packet, ipHeader, header);

    if (protocol == 6 || protocol == 17) printTcpUdpPorts(protocol, ipHeader, packet);

    printPacketData(packet, header->caplen);
}

/**
 * Main fuction
 * @param argc
 * @param argv
 * @return
 */
int main(int argc, char **argv) {
    const char *interface = nullptr;
    const char *port = nullptr;
    int num_packets = 1;

    pcap_t *handle; // Handle for capture

    string filter; // filter for analysis
    string no_port_filter; // filter for analysis

    int opt;
    while ((opt = getopt(argc, argv, "i:p:tn:tu-:")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'p':
                port = optarg;
                break;
            case 't':
                filter += " or tcp";
                break;
            case 'u':
                filter += " or udp";
                break;
            case 'n':
                num_packets = std::stoi(optarg);
                break;
            case '-':
                if (strcmp(optarg, "interface") == 0) {
                    interface = argv[optind];
                } else if (strcmp(optarg, "tcp") == 0) {
                    filter += " or tcp";
                } else if (strcmp(optarg, "udp") == 0) {
                    filter += " or udp";
                } else if (strcmp(optarg, "arp") == 0) {
                    no_port_filter += " or arp";
                } else if (strcmp(optarg, "ndp") == 0) {
                    no_port_filter += " or icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)";
                } else if (strcmp(optarg, "icmp4") == 0) {
                    no_port_filter += " or icmp[0] == 8";
                } else if (strcmp(optarg, "icmp6") == 0) {
                    no_port_filter += " or icmp6[0] == 128 or icmp6[0] == 129";
                } else if (strcmp(optarg, "igmp") == 0) {
                    no_port_filter += " or igmp";
                } else if (strcmp(optarg, "mld") == 0) {
                    no_port_filter += " or (icmp6 and icmp6[0] == 143)";
                } else if (strcmp(optarg, "port") == 0) {
                    port = argv[optind];
                } else {
                    usage();
                    return 1;
                }
                break;
            default:
                usage();
                return 1;
        }
    }
    // if port specified
    if (port != nullptr) {
        if (filter.starts_with(" or ")) filter.erase(0, 4);
        filter = '(' + filter + " src port " + port + " or " + "dst port " + port + ')' + no_port_filter;
    } else {
        filter = filter + no_port_filter;
    }
    // remove start " or " from string
    if (filter.starts_with(" or ")) filter.erase(0, 4);

    // Print interfaces
    if (!interface && !port && filter.empty()) {
        printInterfaces();
    } else if (!interface) {
        cerr << "No interface selected" << endl;
        usage();
        exit(EXIT_FAILURE);
    } else {
        char errbuff[PCAP_ERRBUF_SIZE];
        bpf_u_int32 net; // Adresa site
        bpf_u_int32 mask; // Netmask

        // get interface
        if (pcap_lookupnet(interface, &net, &mask, errbuff) == -1) {
            fprintf(stderr, "Could not get netmask for device %s: %s\n", interface, errbuff);
            net = 0;
            mask = 0;
        }

        // Open interface for sniffing
        handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuff);
        if (handle == nullptr) {
            fprintf(stderr, "Could not open device %s: %s\n", interface, errbuff);
            exit(EXIT_FAILURE);
        }

        // Set filters
        struct bpf_program fp{};
        if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
            cerr << "Could not parse filter: " << filter << pcap_geterr(handle) << endl;
            exit(EXIT_FAILURE);
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            cerr << "Could not install filter: " << filter << pcap_geterr(handle) << endl;
            exit(EXIT_FAILURE);
        }

        // Turn on promisc mode
        if (pcap_set_promisc(handle, 1) == -1) {
            cerr << "Could not set promisc mode: " << pcap_geterr(handle) << endl;
            exit(EXIT_FAILURE);
        }

        // Loop for catching pakcet
        if (pcap_loop(handle, num_packets, parsePacket, nullptr) == -1) {
            cerr << "Could not loop: " << pcap_geterr(handle) << endl;
        }

        //Free handle and end of program
        pcap_freecode(&fp);
        pcap_close(handle);
        return 0;
    }
}

