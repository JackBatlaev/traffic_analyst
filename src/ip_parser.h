#ifndef IP_PARSER_H
#define IP_PARSER_H

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>
/**
 * @brief Разбирает IP-заголовок пакета.
 *
 * @param ip_packet Указатель на начало IP-заголовка.
 * @param len Длина данных, доступных для IP-заголовка и его полезной нагрузки (payload), начиная с IP-заголовка. 
 * @return u_int8_t возвращает номер протокола транспортного уровня, или 0 в случае ошибки.
 *
 */
u_int8_t parse_ipv4_header(const u_char *ip_packet, bpf_u_int32 len);

#endif