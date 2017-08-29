CC := gcc

CFLAGS = -Wall -Wextra -Os -std=c99 -pedantic -fstack-protector-all
CFLAGS += $(USER_CFLAGS)

LDFLAGS = -shared
LDFLAGS += $(USER_LDFLAGS)

BIN = libhypodermicw.so

all: libhypodermicw.so

$(BIN): ptrace.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
	ln -rs $@ ../ # GNU extension


clean:
	rm -f $(BIN)
	rm -f ../$(BIN)

.PHONY: all clean
