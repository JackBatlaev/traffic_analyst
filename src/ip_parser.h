#ifndef IP_PARSER_H
#define IP_PARSER_H

#include <netinet/ip.h>
#include <arpa/inet.h>
#include <pcap.h>
/**
 * @brief Структура для хранения результата разбора IPv4-заголовка.
 *
 * @param transport_protocol Номер протокола транспортного уровня (TCP, UDP, ICMP и т.д.) 
 *                              0, если произошла ошибка или протокол не определен.
 * @param payload_ptr Указатель на начало данных транспортного уровня (IP payload).
                        NULL, если произошла ошибка.
 * @param payload_available_len  Длина доступных данных для транспортного уровня.
 *
 */
typedef struct {
    u_int8_t  transport_protocol;   
    const u_char *payload_ptr;      
    bpf_u_int32 payload_available_len; 
    // (Опционально) Дополнительная информация из IP-заголовка, если она нужна вызывающей стороне
} ipv4_parse_result_t;


/**
 * @brief Разбирает IPv4-заголовок пакета.
 *
 * @param ip_packet Указатель на начало IP-заголовка.
 * @param len Длина доступных данных, начиная с ip_packet.
 * @return ipv4_parse_result_t Структура с результатами разбора.
 *                             Поле transport_protocol будет 0 и payload_ptr будет NULL в случае ошибки.
 */
ipv4_parse_result_t parse_ipv4_header(const u_char *ip_packet, bpf_u_int32 len);


// Структура для хранения IPv4-заголовка (Пока не используется)
typedef struct {
    u_int8_t  version;
    u_int8_t  ihl; // Длина заголовка в байтах
    u_int8_t  tos;
    u_int16_t total_length; // В хостовом порядке
    u_int16_t identification; 
    u_int8_t  flags_df;
    u_int8_t  flags_mf;
    u_int16_t fragment_offset; // Сдвинутое значение
    u_int8_t  ttl;
    u_int8_t  protocol;
    u_int16_t header_checksum;
    struct in_addr  source_ip;
    struct in_addr  destination_ip;
} parsed_ipv4_header_t;




#endif