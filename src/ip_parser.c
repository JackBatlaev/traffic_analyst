#include "ip_parser.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#ifndef IP_MIN_HEADER_LEN
#define IP_MIN_HEADER_LEN 20
#endif

ipv4_parse_result_t parse_ipv4_header(const u_char *ip_packet,
                                      bpf_u_int32 len) {
  ipv4_parse_result_t result;
  // Инициализируем результат нулями
  memset(&result, 0, sizeof(ipv4_parse_result_t));

  const struct ip *fixed_part_header; // Объявляем указатель
  u_int32_t actual_header_length_bytes;
  u_int8_t version;
  u_int8_t ihl_in_words;

  if (len < 1) {
    printf("  [IPv4] Пакет слишком короткий для чтения первого байта (длина: "
           "%u)\n",
           len);
    return result; // Ошибка
  }

  u_int8_t first_byte = *((u_int8_t *)ip_packet);
  version = (first_byte >> 4) & 0x0F; // Версия
  ihl_in_words = first_byte & 0x0F;   // IHL
  actual_header_length_bytes =
      ihl_in_words * 4; // Реальная длина IP-заголовка в байтах

  // Проверяем корректность версии и IHL
  if (version != 4) {
    printf("  [IPv4] Неверная версия IP: %u (ожидалось 4)\n", version);
    return result;
  }

  if (actual_header_length_bytes < 20) {
    printf("  [IPv4] Некорректная длина заголовка IHL: %u слов (реальная длина "
           "%u байт, мин. 20 байт)\n",
           ihl_in_words, actual_header_length_bytes);
    return result;
  }

  // Проверяем, достаточно ли данных для полного заголовка (включая опции)
  if (len < actual_header_length_bytes) {
    printf("  [IPv4] Пакет слишком короткий для полного IP-заголовка (длина: "
           "%u, нужно: %u)\n",
           len, actual_header_length_bytes);
    return result; // Ошибка
  }

  // Накидываем структуру
  fixed_part_header = (const struct ip *)ip_packet;

  // Выводим информацию
  printf("  [IPv4 заголовок]\n");
  printf("    Версия: %u\n", version);
  printf("    Длина заголовка (IHL): %u байт (%u слов по 4 байта)\n",
         actual_header_length_bytes, ihl_in_words);
  printf("    Тип сервиса (TOS): 0x%02x\n", fixed_part_header->ip_tos);
  printf("    Общая длина IP-пакета: %u байт\n",
         ntohs(fixed_part_header->ip_len));
  printf("    Идентификатор: 0x%04x\n", ntohs(fixed_part_header->ip_id));
  printf("    Время жизни (TTL): %u\n", fixed_part_header->ip_ttl);
  printf("    Протокол: %u", fixed_part_header->ip_p);

  switch (fixed_part_header->ip_p) {
  case IPPROTO_TCP:
    printf(" (TCP)\n");
    break;
  case IPPROTO_UDP:
    printf(" (UDP)\n");
    break;
  case IPPROTO_ICMP:
    printf(" (ICMP)\n");
    break;

  default:
    printf(" (Неизвестный: %d)\n", fixed_part_header->ip_p);
    break;
  }
  printf("    Контрольная сумма заголовка: 0x%04x\n",
         ntohs(fixed_part_header->ip_sum));

  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &(fixed_part_header->ip_src), src_ip_str, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &(fixed_part_header->ip_dst), dst_ip_str, INET_ADDRSTRLEN);
  printf("    IP источника: %s\n", src_ip_str);
  printf("    IP назначения: %s\n", dst_ip_str);

  if (actual_header_length_bytes > IP_MIN_HEADER_LEN) {
    printf("  В IP-заголовке есть опции!\n");
    u_int32_t options_part_length =
        actual_header_length_bytes - IP_MIN_HEADER_LEN;
    // const u_char *options_start_ptr = ip_packet + IP_MIN_HEADER_LEN; //
    // (void)options_start_ptr; для заглушки
    printf("    Длина опциональной части: %u байт\n", options_part_length);
    // TODO: Разбор или вывод опций, если нужно
  } else {
    // printf("  IP-заголовок без опций (стандартные 20 байт).\n");
  }

  // const u_char *transport_protocol_data_ptr = ip_packet +
  // actual_header_length_bytes; (void)transport_protocol_data_ptr; // Заглушка,
  result.transport_protocol = fixed_part_header->ip_p;
  result.payload_ptr = ip_packet + actual_header_length_bytes;
  result.payload_available_len = len - actual_header_length_bytes;

  return result; // Возвращаем сохраненное значение ip_p
}