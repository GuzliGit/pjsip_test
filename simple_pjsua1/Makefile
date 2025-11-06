CC_x86_64 = gcc
CC_ARM64 = aarch64-linux-gnu-gcc

BIN_DIR = bin
OBJ_DIR = objs

CFLAGS = $(shell pkg-config --cflags --libs libpjproject) -fsanitize=address

TARGET_x86_64 = $(BIN_DIR)/answerphone
TARGET_ARM64 = $(BIN_DIR)/answerphone-arm

SRC = main.c answerphone.c
OBJS_x86_64 = $(patsubst %.c, $(OBJ_DIR)/%-x86_64.o, $(SRC))
OBJS_ARM64 = $(patsubst %.c, $(OBJ_DIR)/%-arm64.o, $(SRC))

all: x86_64

x86_64: $(OBJS_x86_64) $(TARGET_x86_64)

$(TARGET_x86_64): $(OBJS_x86_64)
	mkdir -p $(BIN_DIR)
	$(CC_x86_64) $^ -g -o $@ $(CFLAGS)

$(OBJ_DIR)/%-x86_64.o: %.c
	mkdir -p $(OBJ_DIR)
	$(CC_x86_64) -c $< -g -o $@ $(CFLAGS)

arm64: $(OBJS_ARM64) $(TARGET_ARM64)

$(TARGET_ARM64): $(OBJS_ARM64)
	mkdir -p $(BIN_DIR)
	$(CC_ARM64) $^ -g -o $@ $(CFLAGS)

$(OBJ_DIR)/%-arm64.o: %.c
	mkdir -p $(OBJ_DIR)
	$(CC_ARM64) -c $< -g -o $@ $(CFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

.PHONY: all x86_64 arm64 clean