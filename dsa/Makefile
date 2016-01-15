OBJ_DIR = obj
BIN_DIR = bin
CRYPTO_SRC_DIR = crypto
CC = gcc
CFLAGS = -O2 -g -Wall -Icrypto

LDFLAGS = -lstdc++

SRCS = $(wildcard crypto/*.cpp)
SRCS += $(wildcard crypto/*.c)
SRCS += main.cpp
CRYPTO_OBJS  = $(patsubst %.cpp,%.o,$(wildcard $(CRYPTO_SRC_DIR)/*.cpp))  

OUTPUT = $(BIN_DIR)/aes

$(BIN_DIR)/dsa: $(CRYPTO_OBJS) $(BIN_DIR) main.o
	$(CC) $(CFLAGS) $(LDFLAGS) $(CRYPTO_OBJS) main.o -o $(BIN_DIR)/dsa

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

%.o: %.cpp $(OBJ_DIR)
	$(CC) -c $(CFLAGS)  $< -o $@




.PHONY: clean
clean: 
	rm -rf $(OBJ_DIR)
	rm -rf $(BIN_DIR)
	rm -f $(CRYPTO_SRC_DIR)/*.o