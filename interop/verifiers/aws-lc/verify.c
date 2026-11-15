/* AWS-LC ML-DSA-87 (pure, external interface) over a cases file. usage: verify CASES.tsv
 * Prints one result line. Exit 0 when no case disagrees with its expected result, 1 when any does, 2 on bad input. */
#include <openssl/base.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/nid.h>
#include <openssl/service_indicator.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hexval(int c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}
/* "-" is empty. Returns malloc'd buffer (never NULL), sets *n; returns NULL only on bad hex. */
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
  int ok = 0;
  EVP_PKEY *key = NULL;
  EVP_MD_CTX *mctx = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  if (cl > 255) return 0;
  key = EVP_PKEY_pqdsa_new_raw_public_key(NID_MLDSA87, pk, pkl);
  if (!key) goto out;
  mctx = EVP_MD_CTX_new();
  if (!mctx) goto out;
  if (!EVP_DigestVerifyInit(mctx, &pctx, NULL, NULL, key)) goto out;
  if (cl > 0 && !EVP_PKEY_CTX_set1_signature_context_string(pctx, ctx, cl)) goto out;
  ok = EVP_DigestVerify(mctx, sig, sl, msg, ml) == 1;
out:
  EVP_MD_CTX_free(mctx);
  EVP_PKEY_free(key);
  return ok;
}

int main(int argc, char **argv) {
  if (argc != 2) { fprintf(stderr, "usage: verify CASES.tsv\n"); return 2; }
  FILE *f = fopen(argv[1], "r");
  if (!f) { fprintf(stderr, "cannot read %s\n", argv[1]); return 2; }
  size_t cap = 0;
  char *line = NULL;
  ssize_t len;
  int n = 0, nbad = 0;
  char bad[8192] = "";
  while ((len = getline(&line, &cap, f)) != -1) {
    if (len > 0 && line[len - 1] == '\n') line[--len] = 0;
    if (len == 0) continue;
    if (len > 0 && line[len - 1] == '\r') line[--len] = 0;
    if ((size_t)len != strlen(line) || strchr(line, '\r')) { fprintf(stderr, "bad line\n"); return 2; }
    char *fld[7];
    int k = 0;
    char *p = line;
    while (k < 7) { fld[k++] = p; char *t = strchr(p, '\t'); if (!t) break; *t = 0; p = t + 1; }
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
  printf("%s: %d cases, %d disagree with the expected result [%s]\n", awslc_version_string(), n, nbad, bad);
  return nbad ? 1 : 0;
}
