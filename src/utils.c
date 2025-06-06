#include "utils.h"
#include "ethernet_parser.h"
#include "ip_parser.h"
#include "thread_pool_queue.h" // для packet_task_t
#include <errno.h>             // для errno
#include <fcntl.h>             // для open
#include <linux/if_packet.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h> // для strcpy, strcat, strerror
#include <time.h>
#include <unistd.h> // для read, close
// Обработчик пакетов
void process_packet_task(
    packet_task_t *task) { // Тут мы получаем структуру для переработки функции
                           // под многопоточность
  const struct pcap_pkthdr *pkthdr =
      &task->header; // Приводим структуру к pkthdr
  const u_char *packet = task->packet_data; // Приводим структуру к packet

  time_t seconds = pkthdr->ts.tv_sec;
  long microseconds = pkthdr->ts.tv_usec;
  char time_buffer[80];
  struct tm time_info;

  if (localtime_r(&seconds, &time_info) == NULL) {
    // Ошибка преобразования времени, можно вывести сообщение или использовать
    // резервный вариант
    perror("localtime_r");
    // В качестве резерва можно просто вывести исходные секунды и микросекунды
    printf("Захвачен пакет длиной %d байт (захвачено %d байт)\n", pkthdr->len,
           pkthdr->caplen);
    printf("Время (raw): %ld.%06ld\n", seconds, microseconds);
    return;
  }
  strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", &time_info);
  printf("Захвачен пакет длиной %d байт\n", pkthdr->len);
  printf("Время: %s.%06ld\n", time_buffer, microseconds);

  // Разбор пакета
  printf("Разбор пакета:\n");
  // Указатели для след уровней парсинга
  const u_char *next_layer_packet = packet + sizeof(struct ether_header);
  bpf_u_int32 next_layer_len = pkthdr->caplen - sizeof(struct ether_header);

  // Заглушка пока
  (void)next_layer_packet; // Явно указываем, что next_layer_packet (пока) не
                           // используется
  (void)next_layer_len; // Явно указываем, что next_layer_len (пока) не
                        // используется
  // Возвращаем EtherType для анализа следующего уровня парсинга

  u_int16_t ether_type = parse_ethernet_header(packet, pkthdr);

  if (ether_type == 0) {
    printf("  Ошибка разбора Ethernet-заголовка или пакет слишком короткий.\n");
    printf("------------------------------------------------------------\n");
    return; // Прекращаем дальнейший разбор этого пакета
  }
  // Теперь, на основе ether_type, мы будем решать, какой парсер вызывать дальше
  switch (ether_type) {
  case ETH_P_IP: // 0x0800 (IPv4)
    printf("  Протокол следующего уровня: IPv4\n");
    ipv4_parse_result_t ip_result =
        parse_ipv4_header(next_layer_packet, next_layer_len);
    if (ip_result.payload_ptr != NULL && ip_result.transport_protocol != 0) {
      switch (ip_result.transport_protocol) {
      case IPPROTO_TCP:
        printf("    Это TCP. Вызываем парсер TCP...\n");
        // parse_tcp_header(ip_result.payload_ptr,
        // ip_result.payload_available_len); // TODO
        break;
      case IPPROTO_UDP:
        printf("    Это UDP. Вызываем парсер UDP...\n");
        // parse_udp_header(ip_result.payload_ptr,
        // ip_result.payload_available_len); // TODO
        break;
      case IPPROTO_ICMP:
        printf("    Это ICMP. Вызываем парсер ICMP...\n");
        // parse_icmp_packet(ip_result.payload_ptr,
        // ip_result.payload_available_len); // TODO
        break;
      default:
        printf("    Неизвестный транспортный протокол IPv4: %u\n",
               ip_result.transport_protocol);
        break;
      }
    }
    break;
  case ETH_P_IPV6: // 0x86DD (IPv6)
    printf("  Протокол следующего уровня: IPv6\n");
    // parse_ipv6_header(next_layer_packet, next_layer_len); // TODO:
    // Реализовать
    break;
  case ETH_P_ARP: // 0x0806 (ARP)
    printf("  Протокол следующего уровня: ARP\n");
    // parse_arp_packet(next_layer_packet, next_layer_len); // TODO: Реализовать
    break;
  default:
    printf("  Протокол следующего уровня (EtherType 0x%04x) пока не "
           "обрабатывается.\n",
           ether_type);
    break;
  }

  // TODO: Здесь дальнейший разбор пакета (IP, TCP/UDP и т.д.)
  printf("------------------------------------------------------------\n");
}

// Печать Mac-адресов интерфейсов
void print_mac_address_sysfs(const char *if_name) {
  char path[256];
  char mac_addr_str[18];
  int fd;
  ssize_t num_read;

  // Путь
  snprintf(path, sizeof(path), "/sys/class/net/%s/address", if_name);

  fd = open(path, O_RDONLY);
  // Отработка ошибки
  if (fd < 0) {
    return; // Не у всех есть MAC
  }

  num_read = read(fd, mac_addr_str, sizeof(mac_addr_str) - 1);
  if (num_read < 0) {
    fprintf(stderr, " Ошибка чтения из %s: %s\n", path, strerror(errno));
    close(fd);
    return;
  }
  // Удаляем символ новой строки
  mac_addr_str[num_read] = '\0'; // Добавляем конец
  if (num_read > 0 && mac_addr_str[num_read - 1] == '\n') {
    mac_addr_str[num_read - 1] = '\0';
  }
  // Проверка на пустоту
  if (strlen(mac_addr_str) > 0) {
    printf("  MAC-адрес: %s\n", mac_addr_str);
  }

  close(fd);
}

// Печать адресов интерфейсов(тут только реализация ip но встроенна и mac)
void print_addresses(pcap_if_t *dev) {
  printf("Имя устройства: %s\n", dev->name);

  if (dev->description) {
    printf("  Описание: %s\n", dev->description);
  }

#ifdef __linux__ // Условная компиляция для Linux
  if (!(dev->flags & PCAP_IF_LOOPBACK)) { // Обычно у loopback нет MAC в /sys
    print_mac_address_sysfs(dev->name);
  }
#endif

  if (dev->addresses == NULL) {
    printf("  У этого устройства нет зарегистрированных IP-адресов.\n");
    return; // Если нет IP, то и нет смысла продолжать для IP-адресов
  }

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
    } else if (sa->sa_family == 17) {
      struct sockaddr_ll *sll = (struct sockaddr_ll *)sa;
      if (sll->sll_halen == 6) { // Проверяем, что это Ethernet MAC-адрес
        printf("  MAC-адрес (из dev->addresses, AF_PACKET): "
               "%02x:%02x:%02x:%02x:%02x:%02x\n",
               sll->sll_addr[0], sll->sll_addr[1], sll->sll_addr[2],
               sll->sll_addr[3], sll->sll_addr[4], sll->sll_addr[5]);
      } else {
        printf("  Обнаружен адрес канального уровня (AF_PACKET), длина %d\n",
               sll->sll_halen);
      }
    } else {
      printf("  Неизвестный тип адреса (семейство: %d)\n", sa->sa_family);
    }
  }
}