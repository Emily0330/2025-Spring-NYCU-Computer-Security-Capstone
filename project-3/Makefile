TARGET = worm
SRC = worm.c
EXECUTABLES = attacker_server crack_attack virus

CC = gcc
CFLAGS = -lssl -lcrypto

# Default rule
all: $(TARGET) chmod_extra

$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC) $(CFLAGS)

chmod_extra:
	chmod +x $(EXECUTABLES)

clean:
	rm -f $(TARGET)
