#pragma once
#include "secret.h"
#include "sodium.h"
#include "aes256gcm.h"
#include <Arduino.h>
#include <WiFi.h>
#include <cstring>
#include <esp_system.h>
#include <mbedtls/gcm.h>
#include <mbedtls/error.h>

#define BYTE256b 32U
#define BYTE512b 64U
#define OK 0b01010101
#define NOK 0b10101010

namespace mtlsp {

int handshake_client(uint8_t master_secret[BYTE256b], Client &client,
                     const uint8_t *raw_fingerprint,
                     size_t raw_fingerprint_length);

int handshake_error(const char *msg);

int send(Client &client, uint8_t *data, const uint32_t data_len);

int recv(Client &client, uint8_t *buf, const uint32_t buf_len);
}; // namespace mtlsp
