char data[] =
"#include <assert.h>\n"
"#include <stddef.h>\n"
"#include <stdint.h>\n"
"#include <stdio.h>\n"
"#include <string.h>\n"
"\n"
"// sha256.h\n"
"\n"
"#define SHA256_BLOCK_SIZE (512 / 8)\n"
"#define SHA256_HASH_SIZE (256 / 8)\n"
"\n"
"struct sha256_ctx {\n"
"  uint64_t nblocks;\n"
"  uint32_t hash[8];\n"
"  uint8_t buflen;\n"
"  uint8_t buf[SHA256_BLOCK_SIZE];\n"
"};\n"
"\n"
"// sha256.c\n"
"\n"
"#define ROTR(X, N) (X >> N | X << 32 - N)\n"
"#define SHR(X, N) (X >> N)\n"
"\n"
"#define CH(X, Y, Z) (X & Y ^ ~X & Z)\n"
"#define MAJ(X, Y, Z) (X & Y ^ X & Z ^ Y & Z)\n"
"#define BSIGMA0(X) (ROTR(X, 2) ^ ROTR(X, 13) ^ ROTR(X, 22))\n"
"#define BSIGMA1(X) (ROTR(X, 6) ^ ROTR(X, 11) ^ ROTR(X, 25))\n"
"#define SSIGMA0(X) (ROTR(X, 7) ^ ROTR(X, 18) ^ SHR(X, 3))\n"
"#define SSIGMA1(X) (ROTR(X, 17) ^ ROTR(X, 19) ^ SHR(X, 10))\n"
"\n"
"static const uint32_t K[64] = {\n"
"    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, //\n"
"    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, //\n"
"    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, //\n"
"    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, //\n"
"    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, //\n"
"    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, //\n"
"    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, //\n"
"    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, //\n"
"    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, //\n"
"    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, //\n"
"    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, //\n"
"    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, //\n"
"    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, //\n"
"    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, //\n"
"    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, //\n"
"    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, //\n"
"};\n"
"\n"
"static const uint32_t H0[8] = {\n"
"    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //\n"
"    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, //\n"
"};\n"
"\n"
"void sha256_init(struct sha256_ctx *ctx) {\n"
"  ctx->nblocks = ctx->buflen = 0;\n"
"  memcpy(ctx->hash, H0, sizeof(H0));\n"
"}\n"
"\n"
"void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len) {\n"
"  while (1) {\n"
"    size_t n = SHA256_BLOCK_SIZE - ctx->buflen;\n"
"    memcpy(ctx->buf + ctx->buflen, data, n = len < n ? len : n);\n"
"    ctx->buflen += n, data += n, len -= n;\n"
"    if (ctx->buflen != SHA256_BLOCK_SIZE)\n"
"      break; // too little data to fill a block\n"
"\n"
"    uint8_t *M = ctx->buf;\n"
"    uint32_t W[64];\n"
"    for (int s = 0, t = 0; t < 16; s += 4, t++)\n"
"      W[t] = M[s + 0] << 24 | M[s + 1] << 16 | M[s + 2] << 8 | M[s + 3] << 0;\n"
"    for (int t = 16; t < 64; t++)\n"
"      W[t] = SSIGMA1(W[t - 2]) + W[t - 7] + SSIGMA0(W[t - 15]) + W[t - 16];\n"
"\n"
"    uint32_t *H = ctx->hash;\n"
"    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];\n"
"    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];\n"
"\n"
"    for (int t = 0; t < 64; t++) {\n"
"      uint32_t T1 = h + BSIGMA1(e) + CH(e, f, g) + K[t] + W[t];\n"
"      uint32_t T2 = BSIGMA0(a) + MAJ(a, b, c);\n"
"      h = g, g = f, f = e, e = d + T1;\n"
"      d = c, c = b, b = a, a = T1 + T2;\n"
"    }\n"
"\n"
"    H[0] += a, H[1] += b, H[2] += c, H[3] += d;\n"
"    H[4] += e, H[5] += f, H[6] += g, H[7] += h;\n"
"\n"
"    ctx->nblocks++;\n"
"    ctx->buflen = 0;\n"
"  }\n"
"}\n"
"\n"
"uint8_t *sha256_final(struct sha256_ctx *ctx) {\n"
"  uint64_t nbits = (ctx->nblocks * SHA256_BLOCK_SIZE + ctx->buflen) * 8;\n"
"\n"
"  ctx->buf[ctx->buflen++] = 0x80; // append '1' bit\n"
"  int delta = SHA256_BLOCK_SIZE - ctx->buflen - 64 / 8;\n"
"  if (delta < 0)\n"
"    delta += SHA256_BLOCK_SIZE;\n"
"  static const uint8_t padding[SHA256_BLOCK_SIZE] = {0x00};\n"
"  sha256_update(ctx, padding, delta);\n"
"\n"
"  for (int i = 0; i < 64 / 8; i++)\n"
"    ctx->buf[ctx->buflen++] = nbits >> (7 - i) * 8;\n"
"  sha256_update(ctx, NULL, 0);\n"
"\n"
"  assert(ctx->buflen == 0); // assert multiple of 512 bits\n"
"\n"
"  // use `ctx->buf` to store the final hash\n"
"  for (int i = 0, j = 0; i < 8; i++) {\n"
"    ctx->buf[j++] = ctx->hash[i] >> 24;\n"
"    ctx->buf[j++] = ctx->hash[i] >> 16;\n"
"    ctx->buf[j++] = ctx->hash[i] >> 8;\n"
"    ctx->buf[j++] = ctx->hash[i] >> 0;\n"
"  }\n"
"\n"
"  return ctx->buf;\n"
"}\n"
"\n"
"// main logic\n"
"\n"
"char prefix[] = \"char data[] =\\n\\\"\";\n"
"char postfix[] = \"\\\";\\n\\n\";\n"
"\n"
"int main(void) {\n"
"  struct sha256_ctx ctx;\n"
"  sha256_init(&ctx);\n"
"\n"
"  sha256_update(&ctx, (uint8_t *)prefix, sizeof(prefix) - 1);\n"
"  for (char *p = data; *p; p++) {\n"
"    switch (*p) {\n"
"    case '\\\\':\n"
"      sha256_update(&ctx, (uint8_t *)\"\\\\\\\\\", 2);\n"
"      break;\n"
"    case '\"':\n"
"      sha256_update(&ctx, (uint8_t *)\"\\\\\\\"\", 2);\n"
"      break;\n"
"    case '\\n':\n"
"      sha256_update(&ctx, (uint8_t *)\"\\\\n\\\"\\n\\\"\", 5);\n"
"      break;\n"
"    default:\n"
"      sha256_update(&ctx, (uint8_t *)p, 1);\n"
"    }\n"
"  }\n"
"  sha256_update(&ctx, (uint8_t *)postfix, sizeof(postfix) - 1);\n"
"  sha256_update(&ctx, (uint8_t *)data, sizeof(data) - 1);\n"
"\n"
"  uint8_t *digest = sha256_final(&ctx);\n"
"  for (int i = 0; i < SHA256_HASH_SIZE; i++)\n"
"    printf(\"%02x\", digest[i]);\n"
"  putchar('\\n');\n"
"}\n"
"";

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// sha256.h

#define SHA256_BLOCK_SIZE (512 / 8)
#define SHA256_HASH_SIZE (256 / 8)

struct sha256_ctx {
  uint64_t nblocks;
  uint32_t hash[8];
  uint8_t buflen;
  uint8_t buf[SHA256_BLOCK_SIZE];
};

// sha256.c

#define ROTR(X, N) (X >> N | X << 32 - N)
#define SHR(X, N) (X >> N)

#define CH(X, Y, Z) (X & Y ^ ~X & Z)
#define MAJ(X, Y, Z) (X & Y ^ X & Z ^ Y & Z)
#define BSIGMA0(X) (ROTR(X, 2) ^ ROTR(X, 13) ^ ROTR(X, 22))
#define BSIGMA1(X) (ROTR(X, 6) ^ ROTR(X, 11) ^ ROTR(X, 25))
#define SSIGMA0(X) (ROTR(X, 7) ^ ROTR(X, 18) ^ SHR(X, 3))
#define SSIGMA1(X) (ROTR(X, 17) ^ ROTR(X, 19) ^ SHR(X, 10))

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, //
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, //
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, //
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, //
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, //
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, //
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, //
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, //
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, //
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, //
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, //
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, //
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, //
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, //
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, //
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2, //
};

static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, //
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, //
};

void sha256_init(struct sha256_ctx *ctx) {
  ctx->nblocks = ctx->buflen = 0;
  memcpy(ctx->hash, H0, sizeof(H0));
}

void sha256_update(struct sha256_ctx *ctx, const uint8_t *data, size_t len) {
  while (1) {
    size_t n = SHA256_BLOCK_SIZE - ctx->buflen;
    memcpy(ctx->buf + ctx->buflen, data, n = len < n ? len : n);
    ctx->buflen += n, data += n, len -= n;
    if (ctx->buflen != SHA256_BLOCK_SIZE)
      break; // too little data to fill a block

    uint8_t *M = ctx->buf;
    uint32_t W[64];
    for (int s = 0, t = 0; t < 16; s += 4, t++)
      W[t] = M[s + 0] << 24 | M[s + 1] << 16 | M[s + 2] << 8 | M[s + 3] << 0;
    for (int t = 16; t < 64; t++)
      W[t] = SSIGMA1(W[t - 2]) + W[t - 7] + SSIGMA0(W[t - 15]) + W[t - 16];

    uint32_t *H = ctx->hash;
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t e = H[4], f = H[5], g = H[6], h = H[7];

    for (int t = 0; t < 64; t++) {
      uint32_t T1 = h + BSIGMA1(e) + CH(e, f, g) + K[t] + W[t];
      uint32_t T2 = BSIGMA0(a) + MAJ(a, b, c);
      h = g, g = f, f = e, e = d + T1;
      d = c, c = b, b = a, a = T1 + T2;
    }

    H[0] += a, H[1] += b, H[2] += c, H[3] += d;
    H[4] += e, H[5] += f, H[6] += g, H[7] += h;

    ctx->nblocks++;
    ctx->buflen = 0;
  }
}

uint8_t *sha256_final(struct sha256_ctx *ctx) {
  uint64_t nbits = (ctx->nblocks * SHA256_BLOCK_SIZE + ctx->buflen) * 8;

  ctx->buf[ctx->buflen++] = 0x80; // append '1' bit
  int delta = SHA256_BLOCK_SIZE - ctx->buflen - 64 / 8;
  if (delta < 0)
    delta += SHA256_BLOCK_SIZE;
  static const uint8_t padding[SHA256_BLOCK_SIZE] = {0x00};
  sha256_update(ctx, padding, delta);

  for (int i = 0; i < 64 / 8; i++)
    ctx->buf[ctx->buflen++] = nbits >> (7 - i) * 8;
  sha256_update(ctx, NULL, 0);

  assert(ctx->buflen == 0); // assert multiple of 512 bits

  // use `ctx->buf` to store the final hash
  for (int i = 0, j = 0; i < 8; i++) {
    ctx->buf[j++] = ctx->hash[i] >> 24;
    ctx->buf[j++] = ctx->hash[i] >> 16;
    ctx->buf[j++] = ctx->hash[i] >> 8;
    ctx->buf[j++] = ctx->hash[i] >> 0;
  }

  return ctx->buf;
}

// main logic

char prefix[] = "char data[] =\n\"";
char postfix[] = "\";\n\n";

int main(void) {
  struct sha256_ctx ctx;
  sha256_init(&ctx);

  sha256_update(&ctx, (uint8_t *)prefix, sizeof(prefix) - 1);
  for (char *p = data; *p; p++) {
    switch (*p) {
    case '\\':
      sha256_update(&ctx, (uint8_t *)"\\\\", 2);
      break;
    case '"':
      sha256_update(&ctx, (uint8_t *)"\\\"", 2);
      break;
    case '\n':
      sha256_update(&ctx, (uint8_t *)"\\n\"\n\"", 5);
      break;
    default:
      sha256_update(&ctx, (uint8_t *)p, 1);
    }
  }
  sha256_update(&ctx, (uint8_t *)postfix, sizeof(postfix) - 1);
  sha256_update(&ctx, (uint8_t *)data, sizeof(data) - 1);

  uint8_t *digest = sha256_final(&ctx);
  for (int i = 0; i < SHA256_HASH_SIZE; i++)
    printf("%02x", digest[i]);
  putchar('\n');
}
