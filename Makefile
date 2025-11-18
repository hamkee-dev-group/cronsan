CC ?= cc
CFLAGS ?= -std=c11 -Wall -Wextra -O2

all: cronsan

cronsan: cronsan.o
	$(CC) $(CFLAGS) -o $@ $^

cronsan.o: cronsan.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f cronsan cronsan.o
