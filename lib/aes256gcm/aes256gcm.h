#pragma once
#include <Arduino.h>
#include <mbedtls/error.h>
#include <mbedtls/gcm.h>

#define AES_KEY_SIZE 32 // 256-bit 密钥
#define IV_SIZE 12      // 12 字节 IV
#define TAG_SIZE 16     // 128-bit 认证标签

int aes256gcm_encrypt(uint8_t *c, uint64_t *clen_p, const uint8_t *m,
                      uint64_t mlen, const uint8_t *ad, uint64_t adlen,
                      const uint8_t *nsec, const uint8_t *npub,
                      const uint8_t *k);

int aes256gcm_decrypt(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec,
                      const uint8_t *c, uint64_t clen, const uint8_t *ad,
                      uint64_t adlen, const uint8_t *npub, const uint8_t *k);
