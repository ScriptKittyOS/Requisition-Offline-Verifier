/* wolfCrypt ML-DSA-87 (pure, external interface) over a cases file. usage: verify CASES.tsv
 * Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
static unsigned char *unhex(const char *s, size_t *n) {
  size_t l = strlen(s);
  if (strcmp(s, "-") == 0) l = 0; else if (l == 0 || l % 2) return NULL;
  unsigned char *b = malloc(l / 2 + 1);
  for (size_t i = 0; i < l / 2; i++) {
    int h = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
    if (h < 0 || lo < 0) { free(b); return NULL; }
    b[i] = (unsigned char)(h * 16 + lo);
  }
  *n = l / 2;
  return b;
}

static int verify(const unsigned char *pk, size_t pkl, const unsigned char *sig, size_t sl,
                  const unsigned char *msg, size_t ml, const unsigned char *ctx, size_t cl) {
  wc_MlDsaKey key;
  int res = 0, ok = 0;
  /* ctxLen is a |byte| in the header (wc_mldsa.h:767-768): a context over 255 bytes cannot be passed. */
  if (cl > 255) return 0;
  if (pkl > 0xffffffffu || sl > 0xffffffffu || ml > 0xffffffffu) return 0;
  if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0) return 0;
  if (wc_MlDsaKey_SetParams(&key, WC_ML_DSA_87) != 0) goto out;
  if (wc_MlDsaKey_ImportPubRaw(&key, pk, (word32)pkl) != 0) goto out;
  if (wc_MlDsaKey_VerifyCtx(&key, sig, (word32)sl, ctx, (byte)cl, msg, (word32)ml, &res) != 0) goto out;
  ok = (res == 1);
out:
  wc_MlDsaKey_Free(&key);
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 2) { fprintf(stderr, "usage: verify CASES.tsv\n"); return 2; }
  if (wolfCrypt_Init() != 0) return 2;
  FILE *f = fopen(argv[1], "r");
  if (!f) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
  size_t cap = 1 << 20;
  char *line = malloc(cap);
  int n = 0, nbad = 0;
  char bad[8192] = "";
  while (fgets(line, (int)cap, f)) {
    line[strcspn(line, "\r\n")] = 0;
    if (!*line) continue;
    char *fld[6];
    int k = 0;
    char *p = line;
    while (k < 6) { fld[k++] = p; char *t = strchr(p, '\t'); if (!t) break; *t = 0; p = t + 1; }
    if (k != 6) { fprintf(stderr, "bad line\n"); return 2; }
    size_t pkl, sl, ml, cl;
    unsigned char *pk = unhex(fld[1], &pkl), *sig = unhex(fld[2], &sl);
    unsigned char *msg = unhex(fld[3], &ml), *ctx = unhex(fld[4], &cl);
    if (!pk || !sig || !msg || !ctx) { fprintf(stderr, "bad hex in case %s\n", fld[0]); return 2; }
    if (strcmp(fld[5], "0") != 0 && strcmp(fld[5], "1") != 0) { fprintf(stderr, "bad expected result in case %s\n", fld[0]); return 2; }
    int got = verify(pk, pkl, sig, sl, msg, ml, ctx, cl);
    n++;
    if (got != (fld[5][0] == '1')) {
      nbad++;
      if (strlen(bad) + strlen(fld[0]) + 3 < sizeof bad) { if (*bad) strcat(bad, ", "); strcat(bad, fld[0]); }
    }
    free(pk); free(sig); free(msg); free(ctx);
  }
  if (ferror(f)) { fprintf(stderr, "read error\n"); return 2; }
  if (n == 0) { fprintf(stderr, "no cases\n"); return 2; }
  printf("wolfSSL %s: %d cases, %d disagree with the expected result [%s]\n", LIBWOLFSSL_VERSION_STRING, n, nbad, bad);
  return nbad ? 1 : 0;
}
