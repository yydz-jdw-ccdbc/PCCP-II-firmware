#include "mtlsp.h"
#include "secret.h"
#include "sodium.h"
#include <Arduino.h>
#include <WiFi.h>
#include <cstring>
#include <esp_system.h>

//---- mtlsp.h ----
#define BYTE256b 32U
#define BYTE512b 64U
#define OK 0b01010101
#define NOK 0b10101010

int mtlsp_handshake(uint32_t (&master_secert)[8]);
int handshake_error(const char *msg);
//----------------

/**
 * @brief 握手函数，为一个 TCP 链接提供一个主密钥
 *
 * @param master_secert 传出参数，256 bits 主密钥
 * @param client WiFi客户端，相当于套接字
 * @param raw_fingerprint 用于prnu认证的原始指纹字节流（一个jpg图片）
 * @param raw_fingerprint_length raw_fingerprint的长度，单位为Byte，默认4K大小
 *
 * @return 0 表示成功， -1 表示失败
 *
 * @details: mtlsp 的含义是 modelled tls protocol，是根据实际需要改版的tls
 */
int mtlsp_handshake(uint8_t master_secert[BYTE256b], WiFiClient &client,
                    const uint8_t *raw_fingerprint,
                    size_t raw_fingerprint_length = 4096) {
  if (sodium_init() < 0) {
    return handshake_error(
        "mtlsp handshake failed, cryptologic moduel initalization failed");
  }
  if (crypto_aead_aes256gcm_is_available() < 0) {
    return handshake_error("mtlsp handshake failed, can't use ase");
  }
  if (WiFi.status() != WL_CONNECTED) {
    return handshake_error("mtlsp handshake failed, wifi not connected");
  }
  // 建立 TCP 连接
  if (client.connect(SERVER_IP, SERVER_PORT)) {
    Serial.println("Connected to MTLSP server");
  } else {
    return handshake_error("Not connected to MTLSP server");
  }
  // 发送 client_random
  uint8_t client_random[BYTE256b];
  esp_fill_random(client_random, sizeof(client_random));
  client.write(client_random, sizeof(client_random));

  // 接收 server 发送的第一波信息
  uint8_t server_random[BYTE256b];  // server_random随机数
  uint8_t server_eph_pub[BYTE256b]; // 服务器临时 ECDH 公钥
  uint8_t sig[BYTE512b];            // Sig(H(Q_s||client_random||server_random))
  client.read(server_random, sizeof(server_random));
  client.read(server_eph_pub, sizeof(server_eph_pub));
  client.read(sig, sizeof(sig));

  // 计算 H(Q_s||client_random||server_random)
  uint8_t tmp_msg[3 * BYTE256b];
  memcpy(tmp_msg, server_eph_pub, BYTE256b);
  memcpy(tmp_msg + BYTE256b, client_random, BYTE256b);
  memcpy(tmp_msg + 2 * BYTE256b, server_random, BYTE256b);
  uint8_t hashed_msg[BYTE256b];
  crypto_hash_sha256(hashed_msg, tmp_msg, sizeof(tmp_msg));

  // 验签
  if (crypto_sign_verify_detached(sig, hashed_msg, 96, server_pub) == -1) {
    client.stop();
    return handshake_error("mtlsp massage verification failed");
  }

  // 确定 client 临时ECDH公私钥
  uint8_t client_eph_sec[BYTE256b]; // 客户端临时 ECDH 私钥
  uint8_t client_eph_pub[BYTE256b]; // 客户端临时 ECDH 公钥
  crypto_kx_keypair(client_eph_sec, client_eph_pub);

  // 生成 Q_c||client_random||server_random 加密盒并发送
  uint8_t tmp_msg[3 * BYTE256b]; // Q_c||client_random||server_random
  memcpy(tmp_msg, client_eph_pub, BYTE256b);
  memcpy(tmp_msg + BYTE256b, client_random, BYTE256b);
  memcpy(tmp_msg + 2 * BYTE256b, server_random, BYTE256b);
  uint8_t cipher_msg[crypto_box_SEALBYTES + sizeof(tmp_msg)];
  crypto_box_seal(cipher_msg, tmp_msg, sizeof(tmp_msg), server_pub);
  client.write(cipher_msg, sizeof(cipher_msg));

  // 验收 OK 信号
  uint8_t sealed_signal[1 + crypto_box_SEALBYTES];
  client.read(sealed_signal, sizeof(sealed_signal));
  uint8_t unsealed_signal;
  crypto_box_seal_open(&unsealed_signal, sealed_signal, sizeof(sealed_signal),
                       client_eph_pub, client_eph_sec);
  if (unsealed_signal != OK) {
    client.stop();
    return handshake_error("mtlsp denied");
  }

  // 计算预主密钥
  uint8_t pre_master_secret[BYTE256b];
  crypto_scalarmult(pre_master_secret, client_eph_sec, server_eph_pub);

  // 计算主密钥
  uint8_t tmp_msg[3 * BYTE256b]; // 预主密钥Z||client_random||server_random
  memcpy(tmp_msg, pre_master_secret, BYTE256b);
  memcpy(tmp_msg + BYTE256b, client_random, BYTE256b);
  memcpy(tmp_msg + 2 * BYTE256b, server_random, BYTE256b);
  crypto_hash_sha256(master_secert, tmp_msg, sizeof(tmp_msg));

  // 加密发送设备原始指纹
  uint8_t enc_fingerprint[raw_fingerprint_length +
                          crypto_aead_aes256gcm_ABYTES]; // 加密后原始指纹
  uint64_t enc_fingerprint_len;                          // 加密后原始指纹长度
  uint8_t npub[crypto_aead_aes256gcm_NPUBBYTES]; // 计数器初始向量，公共随机数
  esp_fill_random(npub, sizeof(npub));
  crypto_aead_aes256gcm_encrypt(enc_fingerprint, &enc_fingerprint_len,
                                raw_fingerprint, raw_fingerprint_length,
                                nullptr, 0, nullptr, npub, master_secert);
  client.write(npub, sizeof(npub));
  client.write(enc_fingerprint, enc_fingerprint_len);
  // uint8_t fingerprint_msg[sizeof(npub) + enc_fingerprint_len];
  // memcpy(fingerprint_msg, npub, sizeof(npub));
  // memcpy(fingerprint_msg + sizeof(npub), enc_fingerprint,
  // enc_fingerprint_len); client.write(fingerprint_msg,
  // sizeof(fingerprint_msg));

  // 确认 OK 信号
  uint8_t final_npub[crypto_aead_aes256gcm_NPUBBYTES];
  uint8_t final_cipher[1 + crypto_aead_aes256gcm_ABYTES];
  uint8_t final_signal;
  client.read(final_npub, sizeof(final_npub));
  client.read(final_cipher, sizeof(final_cipher));
  crypto_aead_aes256gcm_decrypt(&final_signal, nullptr, nullptr, final_cipher,
                                sizeof(final_cipher), nullptr, 0, final_npub,
                                master_secert);
  if(final_signal!=OK) {
    return handshake_error("device may not registed");
  }

  // 握手成功，(client, master) 可为消息传输模块所用
  return 0;
}

/**
 * @brief 用于为 handshake 函数生成错误日志并返回-1的函数
 * @param msg 输出的错误信息
 */
int handshake_error(const char *msg) {
  Serial.println(msg);
  return -1;
}