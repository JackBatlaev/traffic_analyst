#include "thread_pool_queue.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUEUE_CAPACITY 100 // Примерный максимальный размер очереди

static packet_task_t
    *task_queue[QUEUE_CAPACITY]; // Сама очередь (циклический буфер)
static int queue_count = 0; // Текущее количество элементов в очереди
static int queue_head = 0; // Индекс для извлечения (голова)
static int queue_tail = 0; // Индекс для добавления (хвост)

static pthread_mutex_t queue_mutex; // Мьютекс для защиты очереди
static pthread_cond_t queue_not_empty_cond;
static pthread_cond_t queue_not_full_cond;

static pthread_t *worker_threads; // Массив для хранения рабочих потоков
static int num_threads_global;
static packet_processing_fn processing_function_handler; // Указатель на функцию
static volatile int keep_running_global = 1; // Флаг для остановки потоков
static void *worker_loop(void *arg);

// --- Реализация функций ---
// --- Добавление пакета---
int queue_init(int num_worker_threads,
               packet_processing_fn processing_function) {
  printf("queue_init: Инициализация с %d потоками.\n", num_worker_threads);
  // Проверка входных данных
  if (num_worker_threads <= 0) {
    fprintf(stderr, "Некорректное количество потоков\n");
    return -1;
  }
  if (processing_function == NULL) {
    fprintf(stderr, "Не передана функция обработки пакетов\n");
    return -1;
  }
  // Сохраняем указатель на функцию
  processing_function_handler = processing_function;
  // Сохраняем количество потоков
  num_threads_global = num_worker_threads;
  // Устанавливаем флаг и переменные управления очередью
  keep_running_global = 1;
  queue_count = 0;
  queue_head = 0;
  queue_tail = 0;
  // Мьютекс, условные переменные
  if (pthread_mutex_init(&queue_mutex, NULL) != 0) {
    perror("queue_init: Ошибка инициализации мьютекса");
    return -1;
  }
  if (pthread_cond_init(&queue_not_empty_cond, NULL) != 0) {
    perror("queue_init: Ошибка инициализации условной переменной "
           "queue_not_empty_cond");
    pthread_mutex_destroy(&queue_mutex);

    return -1;
  }
  if (pthread_cond_init(&queue_not_full_cond, NULL) != 0) {
    perror("queue_init: Ошибка инициализации условной переменной "
           "queue_not_full_cond");
    pthread_cond_destroy(&queue_not_empty_cond);
    pthread_mutex_destroy(&queue_mutex);

    return -1;
  }
  // Выделяем память под worker_threads
  worker_threads = malloc(num_worker_threads * sizeof(pthread_t));
  if (worker_threads == NULL) {
    perror("queue_init: Ошибка выделения памяти для worker_threads");
    pthread_cond_destroy(&queue_not_empty_cond);
    pthread_cond_destroy(&queue_not_full_cond);
    pthread_mutex_destroy(&queue_mutex);

    return -1;
  }

  // Создаем и запускаем рабочие потоки (каждый будет выполнять
  // worker_loop)
  for (int i = 0; i < num_worker_threads; i++) {
    int result = pthread_create(&worker_threads[i], NULL, worker_loop,
                                (void *)(intptr_t)i);
    if (result != 0) {
      fprintf(stderr, "Ошибка создания потока #%d: %s\n", i, strerror(result));

      pthread_mutex_lock(&queue_mutex); // Захватываем для избежания гонки

      keep_running_global = 0;
      pthread_cond_broadcast(&queue_not_empty_cond);
      pthread_cond_broadcast(&queue_not_full_cond);
      pthread_mutex_unlock(&queue_mutex); // Освобождаем

      for (int j = 0; j < i;
           ++j) { // j < i что бы не особождать не созданные потоки
        if (pthread_join(worker_threads[j], NULL) != 0) {
          char err_buf[256];
          snprintf(err_buf, sizeof(err_buf),
                   "queue_init: Ошибка при pthread_join для потока %d во "
                   "время очистки",
                   j);
          perror(err_buf);
        }
      }
      free(worker_threads);
      worker_threads =
          NULL; // Освобождаем массивы и указатели, мьютексы и переменные

      pthread_cond_destroy(&queue_not_full_cond);
      pthread_cond_destroy(&queue_not_empty_cond);
      pthread_mutex_destroy(&queue_mutex);
      return -1;
    }
  }
  printf("queue_init: Инициализация %d рабочих потоков завершена успешно.\n",
         num_threads_global);
  return 0;
}
// --- Добавление пакета ---
void queue_add_packet(const struct pcap_pkthdr *pkthdr,
                      const u_char *packet_content) {
  printf("queue_add_packet: Добавлен пакет, caplen %d.\n", pkthdr->caplen);

  // Заблокировать мьютекс
  pthread_mutex_lock(&queue_mutex);

  // Подождать, если очередь полна (на queue_not_full_cond)
  while (queue_count == QUEUE_CAPACITY && keep_running_global) {
    printf("Продюсер: очередь полна (%d), ожидание...\n", queue_count);
    pthread_cond_wait(&queue_not_full_cond, &queue_mutex);
    printf("Продюсер: проснулся после ожидания на queue_not_full_cond.\n");
  }
  if (!keep_running_global) {
    pthread_mutex_unlock(&queue_mutex);
    // printf("Продюсер: остановка, пакет не будет добавлен.\n");
    return;
  }

  // Выделяем память под packet_task_t и packet_task_t->packet_data
  packet_task_t *new_task = malloc(sizeof(*new_task));
  if (new_task == NULL) {
    perror("queue_add_packet: Ошибка malloc для packet_task_t");
    pthread_mutex_unlock(&queue_mutex); // Освободить мьютекс перед выходом
    // Можно сделать более сложную логику обработки ошибок!!!!!!!!!!!!
    return;
  }
  new_task->packet_data = (u_char *)malloc(pkthdr->caplen); // Используем caplen
  if (new_task->packet_data == NULL) {
    perror("queue_add_packet: Ошибка malloc для packet_data");
    free(new_task); // Освободить память для структуры
    pthread_mutex_unlock(&queue_mutex);
    return;
  }

  // Скопировать pkthdr и packet_content в новую задачу
  new_task->header = *pkthdr; // Копирование структуры заголовка pcap
  memcpy(new_task->packet_data, packet_content, pkthdr->caplen);

  // Добавить задачу в task_queue, обновить queue_tail, queue_count
  task_queue[queue_tail] = new_task;
  queue_tail = (queue_tail + 1) % QUEUE_CAPACITY;
  queue_count++;
  printf("Продюсер: пакет добавлен. Задач в очереди: %d\n", queue_count);

  // Сигнализировать, что очередь не пуста (queue_not_empty_cond)
  pthread_cond_signal(&queue_not_empty_cond);
  pthread_mutex_unlock(&queue_mutex);
}
// --- Закрытие очереди ---
void queue_shutdown() {
  printf("queue_shutdown: Завершение работы.\n");
  // Установить keep_running_global = 0

  // Разбудить все потоки (broadcast на обе условные переменные)
  pthread_mutex_lock(&queue_mutex);
  keep_running_global = 0;
  printf("queue_shutdown: Отправка broadcast на условные переменные...\n");
  pthread_cond_broadcast(&queue_not_empty_cond);
  pthread_cond_broadcast(&queue_not_full_cond);
  pthread_mutex_unlock(&queue_mutex);

  // Дождаться завершения всех рабочих потоков (pthread_join)
  printf("queue_shutdown: Ожидание завершения %d рабочих потоков...\n",
         num_threads_global);
  if (worker_threads) { // Проверка, что worker_threads был выделен
    for (int i = 0; i < num_threads_global; i++) {
      if (pthread_join(worker_threads[i], NULL) != 0) {
        // Логирование ошибки pthread_join
        char err_buf[256];
        snprintf(err_buf, sizeof(err_buf),
                 "queue_shutdown: Ошибка pthread_join для потока %d", i);
        perror(err_buf);
      } else {
        // printf("queue_shutdown: Рабочий поток %d успешно завершен.\n", i);
      }
    }
  }
  printf("queue_shutdown: Все рабочие потоки должны были завершиться.\n");

  // Освободить память, выделенную для worker_threads
  printf("queue_shutdown: Очистка оставшихся задач в очереди (если есть)...\n");
  pthread_mutex_lock(&queue_mutex);
  int freed_tasks_count = 0;
  while (queue_count > 0) {
    packet_task_t *task = task_queue[queue_head];
    task_queue[queue_head] = NULL; // Хорошая практика
    queue_head = (queue_head + 1) % QUEUE_CAPACITY;
    queue_count--;
    if (task) {
      if (task->packet_data) {
        free(task->packet_data);
      }
      free(task);
      freed_tasks_count++;
    }
  }
  if (freed_tasks_count > 0) {
    printf("queue_shutdown: Освобождено %d необработанных задач из очереди.\n",
           freed_tasks_count);
  }
  pthread_mutex_unlock(&queue_mutex);

  // Уничтожить мьютекс и условные переменные
  printf("queue_shutdown: Освобождение основных ресурсов...\n");
  if (worker_threads != NULL) {
    free(worker_threads);
    worker_threads = NULL;
  }
  if (pthread_mutex_destroy(&queue_mutex) != 0) {
    perror("queue_shutdown: Ошибка pthread_mutex_destroy");
  }
  if (pthread_cond_destroy(&queue_not_empty_cond) != 0) {
    perror("queue_shutdown: Ошибка pthread_cond_destroy (not_empty)");
  }
  if (pthread_cond_destroy(&queue_not_full_cond) != 0) {
    perror("queue_shutdown: Ошибка pthread_cond_destroy (not_full)");
  }

  printf("queue_shutdown: Завершение работы пула потоков выполнено.\n");
}

// --- Функция, которую будет выполнять каждый рабочий поток ---
static void *worker_loop(void *arg) {
  int thread_id = (int)(intptr_t)arg;
  printf("Рабочий поток %d запущен.\n", thread_id);

  while (1) {
    packet_task_t *task = NULL;
    // Блокируем мьютекс
    pthread_mutex_lock(&queue_mutex);

    // Подождать, если очередь пуста И keep_running_global == 1 (на
    // queue_not_empty_cond)
    while (queue_count == 0 && keep_running_global) {
      printf("Поток %d: очередь пуста, ожидание...\n", thread_id);
      pthread_cond_wait(&queue_not_empty_cond, &queue_mutex);
      printf("Поток %d: проснулся\n", thread_id);
    }
    // Если keep_running_global == 0 И очередь пуста, выйти из цикла
    if (!keep_running_global && queue_count == 0) {
      pthread_mutex_unlock(&queue_mutex);
      printf("Поток %d: выход, keep_running=0, очередь пуста\n", thread_id);
      break; // Выход из главного цикла while(1)
    }
    if (queue_count == 0) {
      pthread_mutex_unlock(&queue_mutex);
      continue; // К следующей итерации главного цикла
    }

    // Извлечь задачу из task_queue, обновить queue_head, queue_count

    task = task_queue[queue_head];
    queue_head = (queue_head + 1) % QUEUE_CAPACITY;
    queue_count--;
    printf("Поток %d: извлек задачу. В очереди: %d\n", thread_id, queue_count);
    // Сигнализировать, что очередь не полна (queue_not_full_cond)
    pthread_cond_signal(&queue_not_full_cond);
    // Освобождаем мьютекс так как извлекли пакет из очереди
    pthread_mutex_unlock(&queue_mutex);

    if (task) {
      printf("Рабочий поток %d взял задачу.\n",
             thread_id /* (unsigned long)pthread_self() */);
      // processing_function_handler(task);
      if (processing_function_handler != NULL) {
        processing_function_handler(task);
      }
      // Освободить память, выделенную для task->packet_data и для
      if (task->packet_data != NULL) {
        free(task->packet_data);
        task->packet_data = NULL;
      }
      free(task);
      task = NULL;
      printf("Поток %d: задача обработана и освобождена\n", thread_id);
    }
  }

  printf("Рабочий поток %d завершается.\n", thread_id);
  return NULL;
}
