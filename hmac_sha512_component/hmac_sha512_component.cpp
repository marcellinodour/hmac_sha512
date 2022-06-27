#include "hmac_sha512.h"
#include "sha512.h"

#include <stdlib.h>
#include <string.h>

#define SHA512_BLOCK_SIZE 128

/* LOCAL FUNCTIONS */

// Concatenate X & Y, return hash.
static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen);

// Wrapper for sha512
static void* sha512(const void* data,
                    const size_t datalen,
                    void* out,
                    const size_t outlen);

// Declared in hmac_sha512.h
size_t hmac_sha512(const void* key,
                   const size_t keylen,
                   const void* data,
                   const size_t datalen,
                   void* out,
                   const size_t outlen) {
  uint8_t k[SHA512_BLOCK_SIZE];
  uint8_t k_ipad[SHA512_BLOCK_SIZE];
  uint8_t k_opad[SHA512_BLOCK_SIZE];
  uint8_t ihash[SHA512_HASH_SIZE];
  uint8_t ohash[SHA512_HASH_SIZE];
  size_t sz;
  int i;

  memset(k, 0, sizeof(k));
  memset(k_ipad, 0x36, SHA512_BLOCK_SIZE);
  memset(k_opad, 0x5c, SHA512_BLOCK_SIZE);

  if (keylen > SHA512_BLOCK_SIZE) {
    // If the key is larger than the hash algorithm's
    // block size, we must digest it first.
    sha512(key, keylen, k, sizeof(k));
  } else {
    memcpy(k, key, keylen);
  }

  for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
    k_ipad[i] ^= k[i];
    k_opad[i] ^= k[i];
  }

  // Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
  //      `H(K XOR opad, H(K XOR ipad, data))`
  H(k_ipad, sizeof(k_ipad), data, datalen, ihash, sizeof(ihash));
  H(k_opad, sizeof(k_opad), ihash, sizeof(ihash), ohash, sizeof(ohash));

  sz = (outlen > SHA512_HASH_SIZE) ? SHA512_HASH_SIZE : outlen;
  memcpy(out, ohash, sz);
  return sz;
}

static void* H(const void* x,
               const size_t xlen,
               const void* y,
               const size_t ylen,
               void* out,
               const size_t outlen) {
  void* result;
  size_t buflen = (xlen + ylen);
  uint8_t* buf = (uint8_t*)malloc(buflen);

  memcpy(buf, x, xlen);
  memcpy(buf + xlen, y, ylen);
  result = sha512(buf, buflen, out, outlen);

  free(buf);
  return result;
}

static void* sha512(const void* data,
                    const size_t datalen,
                    void* out,
                    const size_t outlen) {
  size_t sz;
  Sha512Context ctx;
  SHA512_HASH hash;

  Sha512Initialise(&ctx);
  Sha512Update(&ctx, data, datalen);
  Sha512Finalise(&ctx, &hash);

  sz = (outlen > SHA512_HASH_SIZE) ? SHA512_HASH_SIZE : outlen;
  return memcpy(out, hash.bytes, sz);
}

