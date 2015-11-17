OBJ_DIR = obj
BIN_DIR = bin

CC_EXEC = gcc
CFLAGS = -Wall -g

OBJECTS = $(OBJ_DIR)/main.o \
		  $(OBJ_DIR)/affine.o

SRCS = main.c \
	   affine.c

OUTPUT = $(BIN_DIR)/affine

$(OUTPUT): $(OBJECTS)
	mkdir -p $(BIN_DIR)
	$(CC_EXEC) $(CFLAGS) -o $(OUTPUT) $(OBJECTS)

$(OBJ_DIR)/main.o: main.c
	mkdir -p $(OBJ_DIR)
	$(CC_EXEC) $(CFLAGS) -c main.c -o $(OBJ_DIR)/main.o

$(OBJ_DIR)/affine.o: affine.c
	mkdir -p $(OBJ_DIR)
	$(CC_EXEC) $(CFLAGS) -c affine.c -o $(OBJ_DIR)/affine.o


.PHONY : clean
clean:
	rm -rf $(OBJ_DIR)
	rm -rf $(BIN_DIR)

.PHONY : install
install: $(OUTPUT)
	mv $(OUTPUT) /usr/local/bin/