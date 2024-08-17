build:
	mkdir -p bin
	gcc -O2 -Wall -Wno-parentheses -Werror -pedantic -Wno-overlength-strings -std=c99 self-sha256.c -o bin/self-sha256

clean:
	rm -rf bin
