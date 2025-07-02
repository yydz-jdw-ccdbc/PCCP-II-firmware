#include "aes256gcm.h"

// #define AES_KEY_SIZE 32 // 256-bit 密钥
// #define IV_SIZE 12      // 12 字节 IV
// #define TAG_SIZE 16     // 128-bit 认证标签

/// AES256-GCM 加密
/// @return 0 成功，其他值为错误代码
int aes256gcm_encrypt(uint8_t *c, uint64_t *clen_p, const uint8_t *m,
                      uint64_t mlen, const uint8_t *ad, uint64_t adlen,
                      const uint8_t *nsec, const uint8_t *npub,
                      const uint8_t *k) {
  // 初始化上下文
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  // 设置密钥
  if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, k, 256) < 0) {
    return -1;
  }

  // 加密
  uint8_t tag[TAG_SIZE];
  if (mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, mlen, npub, IV_SIZE,
                                ad, adlen, m, c, TAG_SIZE, tag)) {
    return -1;
  }
  *clen_p = mlen + TAG_SIZE;

  // 组合
  memcpy(c + mlen, tag, TAG_SIZE);

  return 0;
}

/// AES256-GCM 解密
/// @return 0 成功，其他值为错误代码
int aes256gcm_decrypt(uint8_t *m, uint64_t *mlen_p, uint8_t *nsec,
                      const uint8_t *c, uint64_t clen, const uint8_t *ad,
                      uint64_t adlen, const uint8_t *npub, const uint8_t *k) {
  // 提取 tag
  if (clen < TAG_SIZE) {
    return -1;
  }
  uint32_t mlen = clen - TAG_SIZE;
  uint8_t *tag = const_cast<uint8_t *>(c) + mlen;

  // 初始化上下文
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  // 设置密钥
  if (mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, k, 256) < 0) {
    
    return -1;
  }

  // 解密验证
  if (mbedtls_gcm_auth_decrypt(&ctx, mlen, npub, IV_SIZE, ad, adlen, tag,
                               TAG_SIZE, c, m) < 0) {
    return -1;
  }

  if (mlen_p) {
    *mlen_p = mlen;
  }

  return 0;
}