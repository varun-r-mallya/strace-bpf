CC=gcc
CFLAGS=-Wall -Wextra -O2

all: call_that_sys

call_that_sys: call_that_sys.c
	$(CC) $(CFLAGS) -o call_that_sys call_that_sys.c

clean:
	rm -f call_that_sys

.PHONY: all clean