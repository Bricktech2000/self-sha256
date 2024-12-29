# self-sha256

_A program that prints its own SHA-256 checksum_

This program outputs the SHA-256 checksum of its own source code without tricks like reading from disk or from environment variables and without language-dependent features like introspection and interpreter functions.

To generate the `data[]` buffer from the source code, use [stringify.vim](stringify.vim) (source it, make a selection, run the macro).

## Usage

```sh
make build
bin/self-sha256
sha256sum self-sha256.c
```
