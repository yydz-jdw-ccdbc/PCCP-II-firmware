#include "camera.h"
#include "esp_camera.h"
#include "mtlsp.h"
#include "secret.h"
#include "xl9555.h"
#include <Arduino.h>
#include <WiFi.h>


void log_memory_init();

void setup() {
  Serial.begin(115200);
  log_memory_init();

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Wifi connecting");

  while (WiFi.status() != WL_CONNECTED) { // 等待拿到 IP
    Serial.print('.');
    delay(500);
  }
  Serial.println("\nWiFi connected, IP: " + WiFi.localIP().toString());

  WiFiClient client;
  if (!client.connect(SERVER_IP, SERVER_PORT)) {
    Serial.println("Failed to reach server");
    return;
  }

  xl9555_init();
  camera_init();
  camera_fb_t *fb = esp_camera_fb_get();
  Serial.printf("fb size: %d\n", fb->len);

  uint8_t master_secret[32];

  mtlsp::handshake_client(master_secret,client,fb->buf,fb->len);
  // mtlsp::handshake_client(master_secret, client, monk_pic, sizeof(monk_pic));
}

void loop() {
  delay(1000);
  Serial.print('.');
}

void log_memory_init() {
  Serial.print("Available RAM size:");
  Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
  Serial.print("EEPROM size:");
  Serial.println(ESP.getFlashChipSize());
}