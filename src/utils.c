#include "utils.h"
#include <errno.h> // для errno
#include <fcntl.h> // для open
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h> // для strcpy, strcat, strerror
#include <time.h>
#include <unistd.h> // для read, close
// Обработчик пакетов
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  (void)user_data; // Явно указываем, что user_data не используется, чтобы
                   // избежать предупреждения
  (void)packet; // Явно указываем, что packet (пока) не используется

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
}

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