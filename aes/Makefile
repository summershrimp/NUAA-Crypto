OBJ_DIR = obj
BIN_DIR = bin

CC_EXEC = gcc
CFLAGS = -O2 -Wall

OBJECTS = $(OBJ_DIR)/main.o \
		  $(OBJ_DIR)/aes.o \
		  $(OBJ_DIR)/sha256.o

SRCS = main.c \
	   sha256.c \
	   aes.c

OUTPUT = $(BIN_DIR)/aes

$(OUTPUT): $(OBJECTS)
	mkdir -p $(BIN_DIR)
	$(CC_EXEC) $(CFLAGS) -o $(OUTPUT) $(OBJECTS)

$(OBJ_DIR)/main.o: main.c
	mkdir -p $(OBJ_DIR)
	$(CC_EXEC) $(CFLAGS) -c main.c -o $(OBJ_DIR)/main.o

$(OBJ_DIR)/aes.o: aes.c
	mkdir -p $(OBJ_DIR)
	$(CC_EXEC) $(CFLAGS) -c aes.c -o $(OBJ_DIR)/aes.o

$(OBJ_DIR)/sha256.o: sha256.c
	mkdir -p $(OBJ_DIR)
	$(CC_EXEC) $(CFLAGS) -c sha256.c -o $(OBJ_DIR)/sha256.o


.PHONY : clean
clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(BIN_DIR)

.PHONY : install
install: $(OUTPUT)
	mv $(OUTPUT) /usr/local/bin/