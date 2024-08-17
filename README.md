# self-sha256

_A program that prints its own SHA-256 checksum_

To generate the `data[]` buffer from the source code, use [stringify.vim](stringify.vim) (source it, make a selection, run the macro).

## Usage

```bash
make build
bin/self-sha256
sha256sum self-sha256.c
```
