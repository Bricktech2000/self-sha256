CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic -std=c99

all: bin/self-sha256

bin/self-sha256: self-sha256.c
	mkdir -p bin/
	$(CC) $(CFLAGS) -Wno-parentheses -Wno-overlength-strings $^ -o $@

clean:
	rm -rf bin/
