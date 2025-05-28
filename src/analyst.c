#include "thread_pool_queue.h"
#include "utils.h"
#include <arpa/inet.h>
#include <pcap.h>
#include <signal.h> // Добавить обработку сигналов
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define STANDART_SIZE 10
static volatile int keep_pcap_loop_running =
    1; // volatile для отключения оптимизации и немедленного изменения
// static pcap_t *global_pcap_handle = NULL; !!!!!!!!!!!!!!!!ТУТ ДОЛЖНА БЫТЬ
// ОТРАБОТКА СИГНАЛОВ

void pcap_packet_callback(u_char *user_args, // Новая функция колбэк
                          const struct pcap_pkthdr *pkthdr,
                          const u_char *packet_content) {
  (void)user_args; // Пока не используется

  if (!keep_pcap_loop_running) { // Проверка флага остановки
    return;
  }
  // Добавляем пакет в очередь пула потоков
  queue_add_packet(pkthdr, packet_content);
}

int main() {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevs;
  pcap_if_t *d;
  char *dev_name = NULL;
  int num_worker_threads;
  tzset(); // Время для проверки ошибки

  // 1. Получить список всех устройств pcap_findalldevs(укзатель на струтуру,
  // буффер для ошибки)
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    fprintf(stderr, "Ошибка при вызове pcap_findalldevs: %s\n", errbuf);
    return 1;
  }
  // Печатаем информацию о интерфейсе(ПОКА)
  for (d = alldevs; d != NULL; d = d->next) {
    print_addresses(d);
  }
  printf("\n");

  // Выбираем интерфейс
  for (d = alldevs; d != NULL; d = d->next) {
    printf("Найден интерфейс: %s", d->name);
    if (d->description) {
      printf(" (%s)", d->description);
    }
    printf("\n");

    // Проверяем, что это не loopback интерфейс и что он "UP" (активен)
    // Флаг PCAP_IF_LOOPBACK проверяет, является ли интерфейс loopback
    // Флаг PCAP_IF_UP (если доступен в вашей версии libpcap) проверяет, активен
    // ли интерфейс Если нет PCAP_IF_UP, можно просто брать первый не-loopback

    // Условие выбора интерфейса:
    // - НЕ loopback (PCAP_IF_LOOPBACK)
    // - Активен (PCAP_IF_UP)
    // - Работает (PCAP_IF_RUNNING)
    if (!(d->flags & PCAP_IF_LOOPBACK) && (d->flags & PCAP_IF_RUNNING) &&
        (d->flags & PCAP_IF_UP)) {

      // Нашли подходящий интерфейс

      dev_name = strdup(d->name);
      if (dev_name == NULL) {
        fprintf(stderr, "Не удалось выделить память для имени устройства\n");
        pcap_freealldevs(alldevs);
        alldevs = NULL;
        return 1;
      }
      printf("Выбран интерфейс: %s\n", dev_name);
      break; // Выходим из цикла, так как нашли подходящее устройство
    }
  }
  // Если не найдено интерфесов
  if (dev_name == NULL) {
    fprintf(stderr,
            "Не найдено подходящего сетевого устройства для захвата.\n");
    if (alldevs) { // Если список был получен, но устройство не выбрано
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

    pcap_freealldevs(alldevs); // Освобождаем список
    return 1;
  }

  // Открыть устройство для захвата
  // Параметры: имя устройства, размер буфера для пакетов (snaplen),
  // promiscuous mode (1 для включения), таймаут (ms), буфер ошибок
  handle = pcap_open_live(dev_name, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "Не удалось открыть устройство %s: %s\n", dev_name, errbuf);
    free(dev_name); // Освобождаем скопированное имя
    return 1;
  }
  num_worker_threads =
      sysconf(_SC_NPROCESSORS_ONLN); // Пока для Linux!!! Переделать с условной
                                     // компиляцией для мака и винды
  if (num_worker_threads <= 0) {
    // Если sysconf не сработал или вернул невалидное значение,
    // используем значение по умолчанию
    fprintf(stderr, "Не удалось определить количество ядер, используем 4 "
                    "потока по умолчанию.\n");
    num_worker_threads = 4;
  } else {
    printf("Обнаружено %d процессорных ядер, используем столько же рабочих "
           "потоков.\n",
           num_worker_threads);
  }

  // Инициализируем очередь
  int res_qeue_int = queue_init(num_worker_threads, process_packet_task);
  if (res_qeue_int < 0) {
    fprintf(stderr, "Не удалось создать очередь %d\n",
            res_qeue_int); // Придумать отработку ошибок(пока они просто -1)
    free(dev_name); // Освобождаем скопированное имя
    pcap_freealldevs(alldevs); // Освобождаем список
  }

  printf("Прослушивание на устройстве %s...\n", dev_name);
  pcap_freealldevs(alldevs);

  // Параметры: хендл pcap, количество пакетов для захвата (-1 для
  // бесконечного), функция-обработчик, пользовательские данные (NULL в данном
  // случае)
  pcap_loop(handle, STANDART_SIZE, pcap_packet_callback,
            NULL); // Пока 100 пакетов

  // Закрыть сессию и освободить ресурсы
  pcap_close(handle);
  queue_shutdown(); // Закрываем очередь
  free(dev_name);   // Освобождаем скопированное имя

  return 0;
}