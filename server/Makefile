# Binary target
TARGET  ?= aesdsocket

#USE AESD DEVICE
USE_AESD_CHAR_DEVICE ?= 1

ifeq ($(USE_AESD_CHAR_DEVICE),1)
  DEFINES += -DUSE_AESD_CHAR_DEVICE
endif

# Compiler and linker
CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
LDFLAGS ?= -fopenmp -lc
CCFLAGS ?= -O3 -Wall -Wextra -pedantic -Wno-sign-compare

# Source and object files
SRC  := server.c
OBJ  := server.o

# Default build rule
all: $(TARGET)

# Linking
$(TARGET): $(OBJ)
	$(CC) $(CCFLAGS) $(LDFLAGS) $(INCLUDES) -o $@ $^

# Compiling
$(OBJ): $(SRC)
	$(CC) $(CCFLAGS) $(DEFINES) -c -o $@ $<

# Run with arguments
run:
	@./$(TARGET) $(ARGUMENTS)

# Clean objects and binaries
clean:
	rm -f $(OBJ) $(TARGET)

# Clean and rebuild
again:
	@make clean
	@make

# Show object files
show:
	@echo "Object file: $(OBJ)"

.PHONY: all run clean again show
