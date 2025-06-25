#include <Arduino.h>

void log_memory_init() {
  Serial.print("Available RAM size:");
  Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
  Serial.print("EEPROM size:");
  Serial.println(ESP.getFlashChipSize());
}