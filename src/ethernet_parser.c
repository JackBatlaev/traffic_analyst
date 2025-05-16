// src/ethernet_parser.c
#include <arpa/inet.h>
#include <stdio.h>

#include "ethernet_parser.h"
#include "utils.h"

// Вспомогательная функция для печати MAC-адреса
static void print_mac(const char *label, const u_char *mac_address) {
  printf("%s: %02x:%02x:%02x:%02x:%02x:%02x\n", label, mac_address[0],
         mac_address[1], mac_address[2], mac_address[3], mac_address[4],
         mac_address[5]);
}

u_int16_t parse_ethernet_header(const u_char *packet,
                                const struct pcap_pkthdr *pkthdr) {
  // const struct ether_header *eth_header;
  const parsed_ethernet_header_t *eth_header;
  // Проверяем достаточна ли длина захваченного пакета для Ethernet-заголовка

  if (pkthdr->caplen < sizeof(parsed_ethernet_header_t)) {
    printf("  [Ethernet] Пакет слишком короткий для Ethernet-заголовка (длина: "
           "%u, нужно: %zu)\n",
           pkthdr->caplen, sizeof(parsed_ethernet_header_t));
    return 0;
  }

  // Приводим указатель на начало пакета к указателю на структуру
  // Ethernet-заголовка

  eth_header = (const parsed_ethernet_header_t *)packet;

  printf("  [Ethernet заголовок]\n");
  print_mac("    MAC назначения", eth_header->ether_dhost);
  print_mac("    MAC источника ", eth_header->ether_shost);

  // Поле ether_type хранится в сетевом порядке байт.
  // Для вывода преобразуем в хостовый порядок байт с помощью ntohs().
  u_int16_t ether_type_host_order = ntohs(eth_header->ether_type);

  // Возвращаем EtherType в сетевом порядке байт, как он был в заголовке.
  return ether_type_host_order;
}