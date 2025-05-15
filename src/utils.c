#include "utils.h"
#include <stdio.h>
// Обработчик пакетов
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  (void)user_data; // Явно указываем, что user_data не используется, чтобы
                   // избежать предупреждения
  (void)packet; // Явно указываем, что packet (пока) не используется

  printf("Захвачен пакет длиной %d байт\n", pkthdr->len);
  printf("Время: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
}
// Печать адресов интерфейсов
void print_addresses(pcap_if_t *dev) {
  printf("Имя устройства: %s\n", dev->name);

  for (struct pcap_addr *a = dev->addresses; a != NULL; a = a->next) {
    struct sockaddr *sa = a->addr;

    // Выводим только IPv4 и IPv6 адреса
    if (sa->sa_family == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)sa;
      char ip_str[INET_ADDRSTRLEN];

      // Преобразуем IP-адрес в строку
      inet_ntop(AF_INET, &(sin->sin_addr), ip_str, INET_ADDRSTRLEN);
      printf("  IPv4: %s\n", ip_str);

      if (a->netmask) {
        struct sockaddr_in *nm = (struct sockaddr_in *)a->netmask;
        char netmask_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(nm->sin_addr), netmask_str, INET_ADDRSTRLEN);
        printf("  Маска подсети: %s\n", netmask_str);
      }

      if (a->broadaddr) {
        struct sockaddr_in *brd = (struct sockaddr_in *)a->broadaddr;
        char broad_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(brd->sin_addr), broad_str, INET_ADDRSTRLEN);
        printf("  Широковещательный адрес: %s\n", broad_str);
      }
    } else if (sa->sa_family == AF_INET6) {
      struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
      char ip6_str[INET6_ADDRSTRLEN];
      inet_ntop(AF_INET6, &sin6->sin6_addr, ip6_str, INET6_ADDRSTRLEN);
      printf("  IPv6: %s\n", ip6_str);
    } else {
      printf("  Неизвестный тип адреса\n");
    }
  }
}