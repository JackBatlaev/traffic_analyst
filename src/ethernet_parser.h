#ifndef ETHERNET_PARSER_H
#define ETHERNET_PARSER_H

#include <netinet/if_ether.h>
#include <pcap.h>

typedef struct {
  u_char ether_dhost[ETHER_ADDR_LEN]; // MAC-адрес назначения
  u_char ether_shost[ETHER_ADDR_LEN]; // MAC-адрес источника
  u_int16_t ether_type; // Тип протокола следующего уровня (в сетевом порядке)
} parsed_ethernet_header_t;

/**
 * @brief Разбираем Ethernet-заголовок пакета.
 *
 * @param packet Указатель на начало Ethernet-кадра.
 * @param pkthdr Указатель на pcap_pkthdr для получения длины пакета.
 * @return u_int16_t Тип протокола следующего уровня (EtherType) в ХОСТОВОМ
 * порядке байт, или 0 в случае ошибки.
 */
u_int16_t parse_ethernet_header(const u_char *packet,
                                const struct pcap_pkthdr *pkthdr);

#endif