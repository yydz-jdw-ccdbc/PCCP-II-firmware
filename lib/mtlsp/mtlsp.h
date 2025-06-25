#pragma once

#define BYTE256b 32U
#define BYTE512b 64U
#define OK 0b01010101
#define NOK 0b10101010

int mtlsp_handshake(uint8_t master_secert[BYTE256b], WiFiClient &client,
                    const uint8_t *raw_fingerprint,
                    size_t raw_fingerprint_length = 4096);
int handshake_error(const char *msg);