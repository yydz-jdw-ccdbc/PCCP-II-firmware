#include "mtlsp.h"

// #define BYTE256b 32U
// #define BYTE512b 64U
// #define OK 0b01010101
// #define NOK 0b10101010

using namespace mtlsp;

/**
 * @brief 握手函数，为一个 TCP 链接提供一个主密钥
 *
 * @param master_secret 传出参数，256 bits 主密钥
 * @param client 客户端，相当于套接字
 * @param raw_fingerprint 用于prnu认证的原始指纹字节流（一个jpg图片）
 * @param raw_fingerprint_length raw_fingerprint的长度，单位为Byte
 *
 * @return int 0 表示成功， -1 表示失败
 *
 * @details: mtlsp 的含义是 modelled tls protocol，是根据实际需要改版的tls
 */
int mtlsp::handshake_client(uint8_t master_secret[BYTE256b], Client &client,
                            const uint8_t *raw_fingerprint,
                            size_t raw_fingerprint_length) {
  if (sodium_init() < 0) {
    return handshake_error(
        "mtlsp handshake failed, cryptologic moduel initalization failed");
  }

  if (WiFi.status() != WL_CONNECTED) {
    return handshake_error("mtlsp handshake failed, wifi not connected");
  }

  if (!client.connected()) {
    return handshake_error("TCP not connected");
  }
  // 发送 client_random
  uint8_t client_random[BYTE256b];
  esp_fill_random(client_random, sizeof(client_random));
  send(client, client_random, sizeof(client_random));

  // 接收 server 发送的第一波信息
  uint8_t server_random[BYTE256b];  // server_random随机数
  uint8_t server_eph_pub[BYTE256b]; // 服务器临时 ECDH 公钥
  uint8_t sig[BYTE512b];            // Sig(H(Q_s||client_random||server_random))
  if (recv(client, server_random, sizeof(server_random)) < 0) {
    return handshake_error("sr not received");
  }
  if (recv(client, server_eph_pub, sizeof(server_eph_pub)) < 0) {
    return handshake_error("Qs not received");
  }
  if (recv(client, sig, sizeof(sig)) < 0) {
    return handshake_error("Sig not received");
  }

  // 计算 H(Q_s||client_random||server_random)
  uint8_t tmp_msg_qscs[3 * BYTE256b];
  memcpy(tmp_msg_qscs, server_eph_pub, BYTE256b);
  memcpy(tmp_msg_qscs + BYTE256b, client_random, BYTE256b);
  memcpy(tmp_msg_qscs + 2 * BYTE256b, server_random, BYTE256b);
  uint8_t hashed_msg[BYTE256b];
  crypto_hash_sha256(hashed_msg, tmp_msg_qscs, sizeof(tmp_msg_qscs));

  // 验签
  if (crypto_sign_verify_detached(sig, hashed_msg, BYTE256b, ed_server_pub) <
      0) {
    client.stop();
    return handshake_error("mtlsp message verification failed");
  }

  Serial.print("DEBUG Q_s: ");
  for (int i = 0; i < 32; ++i) {
    Serial.printf("%02x", server_eph_pub[i]);
  }
  Serial.println();

  // 确定 client 临时ECDH公私钥
  uint8_t client_eph_sec[BYTE256b]; // 客户端临时 ECDH 私钥
  uint8_t client_eph_pub[BYTE256b]; // 客户端临时 ECDH 公钥
  crypto_kx_keypair(client_eph_pub, client_eph_sec);

  Serial.print("DEBUG Q_c: ");
  for (int i = 0; i < 32; ++i) {
    Serial.printf("%02x", client_eph_pub[i]);
  }
  Serial.println();

  // 加密并发送 Q_c||client_random||server_random
  uint8_t x_server_pub[BYTE256b];
  if (crypto_sign_ed25519_pk_to_curve25519(x_server_pub, ed_server_pub) < 0) {
    return handshake_error("key transform failed");
  }
  uint8_t tmp_msg_qccs[3 * BYTE256b]; // Q_c||client_random||server_random
  memcpy(tmp_msg_qccs, client_eph_pub, BYTE256b);
  memcpy(tmp_msg_qccs + BYTE256b, client_random, BYTE256b);
  memcpy(tmp_msg_qccs + 2 * BYTE256b, server_random, BYTE256b);
  uint8_t cipher_msg[crypto_box_SEALBYTES + sizeof(tmp_msg_qccs)];
  crypto_box_seal(cipher_msg, tmp_msg_qccs, sizeof(tmp_msg_qccs), x_server_pub);
  send(client, cipher_msg, sizeof(cipher_msg));

  // 验收 OK 信号
  uint8_t sealed_signal[1 + crypto_box_SEALBYTES];
  if (recv(client, sealed_signal, sizeof(sealed_signal)) < 0) {
    return handshake_error("OK1 not received");
  }
  uint8_t unsealed_signal;
  if (crypto_box_seal_open(&unsealed_signal, sealed_signal,
                           sizeof(sealed_signal), client_eph_pub,
                           client_eph_sec) < 0) {
    return handshake_error("ecc crypto error");
  }
  if (unsealed_signal != OK) {
    client.stop();
    return handshake_error("mtlsp denied");
  }

  // 计算预主密钥
  uint8_t pre_master_secret[BYTE256b];
  if (crypto_scalarmult_curve25519(pre_master_secret, client_eph_sec, server_eph_pub) <
      0) {
    return handshake_error("scalarmult crypto error");
  };

  Serial.print("DEBUG pre_master_secret: ");
  for (int i = 0; i < 32; ++i) {
    Serial.printf("%02x", pre_master_secret[i]);
  }
  Serial.println();

  // 计算主密钥 M = H(Z || client_random || server_random)
  uint8_t tmp_msg_zcs[3 * BYTE256b]; // Z||client_random||server_random
  memcpy(tmp_msg_zcs, pre_master_secret, BYTE256b);
  memcpy(tmp_msg_zcs + BYTE256b, client_random, BYTE256b);
  memcpy(tmp_msg_zcs + 2 * BYTE256b, server_random, BYTE256b);
  crypto_hash_sha256(master_secret, tmp_msg_zcs, sizeof(tmp_msg_zcs));

  Serial.print("DEBUG master_secret: ");
  for (int i = 0; i < 32; ++i) {
    Serial.printf("%x", master_secret[i]);
  }
  Serial.println();

  // 加密发送设备原始指纹
  uint8_t *enc_fingerprint = (uint8_t *)pvPortMalloc(
      raw_fingerprint_length + crypto_aead_aes256gcm_ABYTES); // 加密后原始指纹
  if(!enc_fingerprint) {
    return handshake_error("pvPortMalloc failed for fingerprint buffer");
}
  uint64_t enc_fingerprint_len; // 加密后原始指纹长度
  uint8_t nonce_client
      [crypto_aead_aes256gcm_NPUBBYTES]; // 计数器初始向量，公共随机数
  esp_fill_random(nonce_client, sizeof(nonce_client));
  aes256gcm_encrypt(enc_fingerprint, &enc_fingerprint_len, raw_fingerprint,
                    raw_fingerprint_length, nullptr, 0, nullptr, nonce_client,
                    master_secret);
  send(client, nonce_client, sizeof(nonce_client));
  send(client, enc_fingerprint, enc_fingerprint_len);
  vPortFree(enc_fingerprint);

  // 确认 OK 信号
  uint8_t nonce_server[crypto_aead_aes256gcm_NPUBBYTES];
  uint8_t final_cipher[1 + crypto_aead_aes256gcm_ABYTES];
  uint8_t final_signal;
  if (recv(client, nonce_server, sizeof(nonce_server)) < 0) {
    return handshake_error("OK2 nonce not received");
  }
  if (recv(client, final_cipher, sizeof(final_cipher)) < 0) {
    return handshake_error("OK2 cipher not received");
  }
  Serial.println("OK confirmed");

  uint64_t mlen;
  if (aes256gcm_decrypt(&final_signal, &mlen, nullptr, final_cipher,
                        sizeof(final_cipher), nullptr, 0, nonce_server,
                        master_secret) < 0) {
    return handshake_error("aes crypto error");
  };

  Serial.println("Decrypt confirmed");

  if (final_signal != OK) {
    return handshake_error("device may not registed");
  }

  // 握手成功，(client, master) 可为消息传输模块所用
  Serial.println("mtlsp handshake succeed!");
  return 0;
}

/**
 * @brief 用于为 handshake 函数生成错误日志并返回-1的函数
 * @param msg 输出的错误信息
 */
int mtlsp::handshake_error(const char *msg) {
  Serial.println(msg);
  return -1;
}

