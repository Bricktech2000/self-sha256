.POSIX:
.SUFFIXES:
CC=gcc
CFLAGS=-O2 -Wall -Wextra -Wpedantic -std=c99

all: bin/self-sha256
bin/:; mkdir bin/
clean:; rm -rf bin/

bin/self-sha256: bin/ self-sha256.c; $(CC) $(CFLAGS) -o $@ self-sha256.c -Wno-parentheses -Wno-overlength-strings
