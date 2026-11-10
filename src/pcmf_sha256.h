#ifndef PCMF_SHA256_H
#define PCMF_SHA256_H
/*
 * PCMF R14 - self-contained SHA-256 / HMAC-SHA256 (C11, FIPS 180-4 / RFC 2104).
 *
 * Rationale: the R10/R11 ingress linked OpenSSL's static libcrypto. On newer
 * toolchains that drags transitive deps (zstd, zlib) and version-dependent
 * APIs. R14 needs zero third-party dependencies for offline deployment, so
 * the two primitives actually used (SHA-256, HMAC-SHA256) are implemented
 * here directly from the published specifications and verified against the
 * NIST FIPS 180-4 and RFC 4231 test vectors in the native selftest.
 */
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

void pcmf_sha256(const void *msg, size_t len, uint8_t out[32]);
/* key_len may be 0..64 for this fixed-call HMAC; longer keys are hashed. */
void pcmf_hmac_sha256(const uint8_t *key, size_t key_len,
                      const void *msg, size_t len, uint8_t out[32]);
/* Constant-time equality for MACs/tags. */
int pcmf_ct_equal(const void *a, const void *b, size_t n);

void pcmf_to_hex(const uint8_t *in, size_t n, char *out /* 2n+1 */);
/* Returns 1 on success; 0 on malformed input (wrong length or bad digit). */
int pcmf_from_hex(const char *in, uint8_t *out, size_t n);

#ifdef __cplusplus
}
#endif
#endif
