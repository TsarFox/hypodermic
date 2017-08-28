CC := gcc

CFLAGS = -Wall -Wextra -Os -std=c99 -pedantic -fstack-protector-all
CFLAGS += $(USER_CFLAGS)

LDFLAGS = -shared
LDFLAGS += $(USER_LDFLAGS)

all: libptracew.so

libtestw.so: ptrace.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
