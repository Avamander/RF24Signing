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
const uint16_t this_node = 00;    // Address of our node in Octal format ( 04,031, etc)
const uint16_t other_node = 01;   // Address of the other node in Octal format

#include "RF24Signing.h"

RF24NetworkHeader header;

struct payload_p {
  payloadmetadata metadata;
  uint32_t time;
  uint8_t count;
};

void setup(void) {
  Serial.begin(115200);
  Serial.println(F("RF24Signing/examples/helloworld_rx/"));
  mesh.setNodeID(1);
  Serial.println(F("RF24Mesh 1/2 ready"));
  mesh.begin();
  Serial.println(F("RF24Mesh ready"));
  SignedNetworkBegin();
  Serial.println(F("RF24Signing ready"));
}

void loop(void) {
  network.update();                  // Check the network regularly
  SignedNetworkUpdate();

  while (UnsignedNetworkAvailable()) {
    RF24NetworkHeader header;
    payload_p payload;
    network.read(header, &payload, sizeof(payload_p));
    Serial.print(F("Payload.time"));
    Serial.print(payload.time);
    Serial.print(F(" payload.count "));
    Serial.println(payload.count);
  }
}
