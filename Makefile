# Makefile

$(info Makefile is being read...)
$(info Current directory is $(CURDIR))

CC = gcc
CFLAGS = -Wall -Wextra -g
CPPFLAGS = -D_GNU_SOURCE
SRC_DIR = src
CPPFLAGS += -I$(SRC_DIR)
LDFLAGS = -lpcap
TARGET = analyst

SRCS := $(shell find $(SRC_DIR) -maxdepth 1 -name '*.c' -type f)
$(info SRCS determined as: [$(SRCS)])

# Новый способ определения OBJS
OBJS :=
TEMP_OBJS :=
$(foreach src_file,$(SRCS), \
    $(eval base_name := $(notdir $(src_file))) \
    $(eval obj_name := $(patsubst %.c,%.o,$(base_name))) \
    $(eval TEMP_OBJS += $(obj_name)) \
)
OBJS := $(strip $(TEMP_OBJS)) # strip убирает лишние пробелы
$(info OBJS determined as (using foreach): [$(OBJS)])

HEADERS := $(shell find $(SRC_DIR) -maxdepth 1 -name '*.h' -type f)
$(info HEADERS determined as: [$(HEADERS)])

# Проверка, что OBJS не пустой
ifneq ($(strip $(OBJS)),)

all: $(TARGET)

$(TARGET): $(OBJS)
	@echo "Linking target: $@"
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: $(SRC_DIR)/%.c $(HEADERS)
	@echo "Compiling: $< -> $@"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

else
all:
	@echo "No source files found or OBJS list is empty. Check SRCS and SRC_DIR."
	@echo "SRCS: [$(SRCS)]"
	@echo "OBJS (from foreach): [$(OBJS)]"
endif

# БЕЗОПАСНАЯ ВЕРСИЯ CLEAN ДЛЯ ТЕСТА
clean:
	@echo "--- Debugging make clean ---"
	@echo "Current directory is: $(CURDIR)"
	@echo "SRC_DIR is: $(SRC_DIR)"
	@echo "SRCS determined as (at clean time): [$(SRCS)]"
	@echo "OBJS determined as (at clean time, from foreach): [$(OBJS)]" # Используем тот же метод вычисления
	@echo "TARGET is: [$(TARGET)]"
	@echo "Would try to execute: rm -f $(OBJS) $(TARGET)"
	rm -f $(OBJS) $(TARGET) # ОСТАВЬТЕ ЗАКОММЕНТИРОВАННЫМ!

.PHONY: all clean