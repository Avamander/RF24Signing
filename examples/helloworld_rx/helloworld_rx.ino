/*
  Copyright (C) 2012 James Coliz, Jr. <maniacbug@ymail.com>
  Copyright (C) 2014 TMRh20
  Copyright (C) 2016 Avamander <avamander@gmail.com>
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.
*/

/**
   Simplest possible example of using RF24Network,

   RECEIVER NODE
   Listens for messages from the transmitter and prints them out.
*/

#include <RF24Mesh.h>
#include <RF24Network.h>
#include <RF24.h>
#include <SPI.h>



RF24 radio(9, 10);                // nRF24L01(+) radio attached using Getting Started board
RF24Network network(radio);      // Network uses that radio
RF24Mesh mesh(radio, network);

#include "RF24Signing.h"

RF24NetworkHeader header;

struct payload_s {
  int sensor_id;
  int sensor_data;
};

struct payload_p {
  PayloadMetadata metadata;
  uint32_t time;
  uint8_t count;
};

unsigned long displayTimer = 0;

void setup(void) {
  delay(500);
  Serial.begin(115200);
  Serial.println(F("RF24Signing/examples/helloworld_rx/"));
  mesh.setNodeID(1);
  Serial.println(F("RF24Mesh 1/2 ready"));
  mesh.begin();
  Serial.println(F("RF24Mesh ready"));
  signed_network_begin(1);
  Serial.println(F("RF24Signing ready"));
}

void loop(void) {
  if (Serial.available() > 0) {
    int abyte = Serial.read();

    switch (abyte) {
      case 'a':
        received_noncelist_print();
        break;
      case 'b':
        sent_noncelist_print();
        break;
      case 'c':
        bufferlist_print();
        break;
      case 'd':

        payload_s payload;
        payload.sensor_id = 123;
        payload.sensor_data = 345;
        bufferlist_add(1, &payload, sizeof(payload_s));
        Serial.println(F("Returned to switch"));
        break;
      case 'e':
        break;
      default:
        break;
    }
  }
  network.update();                  // Check the network regularly
  signed_network_update();

  if (millis() - displayTimer > 1000) {
    Serial.println(millis());
    displayTimer = millis();
    if (!mesh.checkConnection()) {
        //refresh the network address
        Serial.println("Renewing Address");
        mesh.renewAddress();
    }
  }
  
  while (UnsignedNetworkAvailable()) {
    Serial.println(F("-"));
    RF24NetworkHeader header;
    payload_p payload;
    network.read(header, &payload, sizeof(payload_p));
    Serial.print(F("Payload.time"));
    Serial.print(payload.time);
    Serial.print(F(" payload.count "));
    Serial.println(payload.count);
  }
}
