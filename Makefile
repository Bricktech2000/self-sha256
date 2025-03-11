CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic -std=c99

all: bin/self-sha256

bin/self-sha256: self-sha256.c | bin/
	$(CC) $(CFLAGS) -Wno-parentheses -Wno-overlength-strings $^ -o $@

bin/:
	mkdir bin/

clean:
	rm -rf bin/
