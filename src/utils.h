#ifndef NET_UTILS_H
#define NET_UTILS_H

#include <arpa/inet.h> // Для AF_INET, AF_INET6, sockaddr_in, sockaddr_in6, inet_ntop
#include <pcap.h> // Для u_char, pcap_pkthdr, pcap_if_t, pcap_addr

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet);

void print_addresses(pcap_if_t *dev);

#endif