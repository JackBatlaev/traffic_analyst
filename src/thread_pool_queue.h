#ifndef THREAD_POOL_QUEUE_H
#define THREAD_POOL_QUEUE_H

#include <pcap.h>
#include <pthread.h>

typedef struct {
  struct pcap_pkthdr header; // Копия заголовка pcap
  u_char *packet_data;       // Копия данных пакета
} packet_task_t;

// 2. Прототип функции, которую будут выполнять рабочие потоки
//    Эта функция будет принимать указатель на задачу и обрабатывать ее.
//    Именно сюда ты "подключишь" свой текущий packet_handler (адаптированный).
typedef void (*packet_processing_fn)(packet_task_t *task);

// 3. Функции для управления пулом потоков и очередью
//    Инициализация: создает очередь, мьютексы, условные переменные,
//    запускает 'num_worker_threads' рабочих потоков.
//    'processing_function' - это указатель на функцию, которая будет
//    обрабатывать пакеты.
int queue_init(int num_worker_threads,
               packet_processing_fn processing_function);

//    Добавление пакета в очередь (будет вызываться из pcap callback)
//    Эта функция должна внутри себя выделить память и скопировать данные.
void queue_add_packet(const struct pcap_pkthdr *pkthdr,
                      const u_char *packet_content);

//    Корректное завершение работы: останавливает добавление новых задач,
//    дает рабочим потокам обработать оставшиеся задачи,
//    освобождает все ресурсы.
void queue_shutdown();

#endif // THREAD_POOL_QUEUE_H