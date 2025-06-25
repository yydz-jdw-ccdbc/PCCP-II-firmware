#include <Arduino.h>

// put function declarations here:
// extern functions
extern void log_memory_init();
// local functions

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);

  log_memory_init();
}

void loop() {
  // put your main code here, to run repeatedly:
}

// put function definitions here:
