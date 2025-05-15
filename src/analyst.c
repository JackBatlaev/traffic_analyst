#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet) {
  printf("Захвачен пакет длиной %d байт\n", pkthdr->len);
  printf("Время: %ld.%06ld\n", pkthdr->ts.tv_sec, pkthdr->ts.tv_usec);
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  pcap_if_t *d;
  char *dev_name = NULL;

  // 1. Получить список всех устройств
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Ошибка при вызове pcap_findalldevs: %s\n", errbuf);
    return 1;
  }

  // 2. Выбрать подходящее устройство
  //    Мы выберем первое не-loopback и активное устройство
  //  Можем выбрать case но пока так
  for (d = alldevs; d != NULL; d = d->next) {
    printf("Найден интерфейс: %s", d->name);
    if (d->description) {
      printf(" (%s)", d->description);
    }
    printf("\n");

    sleep(100);

    // Проверяем, что это не loopback интерфейс и что он "UP" (активен)
    // Флаг PCAP_IF_LOOPBACK проверяет, является ли интерфейс loopback
    // Флаг PCAP_IF_UP (если доступен в вашей версии libpcap) проверяет, активен
    // ли интерфейс Если нет PCAP_IF_UP, можно просто брать первый не-loopback
    if (!(d->flags & PCAP_IF_LOOPBACK) && (d->flags & PCAP_IF_RUNNING) &&
        (d->flags & PCAP_IF_UP)) { // PCAP_IF_RUNNING и PCAP_IF_UP часто
                                   // означают, что интерфейс готов
      // Нашли подходящий интерфейс
      // Нужно скопировать имя, так как alldevs будет освобожден
      dev_name = strdup(d->name);
      if (dev_name == NULL) {
        fprintf(stderr, "Не удалось выделить память для имени устройства\n");
        pcap_freealldevs(alldevs);
        return 1;
      }
      printf("Выбран интерфейс: %s\n", dev_name);
      break; // Выходим из цикла, так как нашли подходящее устройство
    }
  }

  if (dev_name == NULL) {
    fprintf(stderr,
            "Не найдено подходящего сетевого устройства для захвата.\n");
    if (alldevs) { // Если список был получен, но устройство не выбрано
      // Можно вывести список всех устройств для отладки
      printf("Доступные устройства:\n");
      for (d = alldevs; d != NULL; d = d->next) {
        printf("- %s", d->name);
        if (d->flags & PCAP_IF_LOOPBACK)
          printf(" (Loopback)");
        if (d->flags & PCAP_IF_UP)
          printf(" (Up)");
        else
          printf(" (Down)");
        if (d->flags & PCAP_IF_RUNNING)
          printf(" (Running)");
        else
          printf(" (Not Running)");
        printf("\n");
      }
    }
    pcap_freealldevs(alldevs); // Освобождаем список в любом случае
    return 1;
  }

  // Открыть устройство для захвата
  // Параметры: имя устройства, размер буфера для пакетов (snaplen),
  // promiscuous mode (1 для включения), таймаут (ms), буфер ошибок
  handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Не удалось открыть устройство %s: %s\n", dev_name, errbuf);
    free(dev_name); // Освобождаем скопированное имя
    pcap_freealldevs(alldevs); // Освобождаем список
    return 1;
  }

  printf("Прослушивание на устройстве %s...\n", dev_name);

  // 3. Освободить список устройств после того, как имя устройства скопировано
  //    и оно больше не нужно
  pcap_freealldevs(alldevs);

  // Начать захват пакетов
  // Параметры: хендл pcap, количество пакетов для захвата (-1 для
  // бесконечного), функция-обработчик, пользовательские данные (NULL в данном
  // случае)
  pcap_loop(handle, -1, packet_handler, NULL);

  // Закрыть сессию и освободить ресурсы
  pcap_close(handle);
  free(dev_name); // Освобождаем скопированное имя

  return 0;
}