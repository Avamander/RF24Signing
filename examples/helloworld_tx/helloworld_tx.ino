/*
  Copyright (C) 2012 James Coliz, Jr. <maniacbug@ymail.com>
  Copyright (C) 2014 TMRh20
  Copyright (C) 2016 Avamander <avamander@gmail.com>
  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  version 2 as published by the Free Software Foundation.
*/

/**
   Simplest possible example of using RF24Network

   TRANSMITTER NODE
   Every 2 seconds, send a payload to the receiver node.
*/

#include <RF24Network.h>
#include <RF24.h>
#include <SPI.h>


RF24 radio(9, 10);

#include "sha256.h"
Sha256Class Sha256;

RF24Network network(radio);          // Network uses that radio
const uint16_t this_node = 01;        // Address of our node in Octal format
const uint16_t other_node = 00;       // Address of the other node in Octal format

const unsigned long interval = 500;//ms  // How often to send 'hello world to the other unit

unsigned long last_sent = 60000;            // When did we last send?
unsigned long packets_sent;          // How many have we sent already


#include "RF24Signing.h"

RF24NetworkHeader header;

int sensor_id;
int sensor_data;

struct payload_s {
  int sensor_id;
  int sensor_data;
};

struct payload_s payload;

void setup(void){
  Serial.begin(115200);
  Serial.println("RF24Network/examples/helloworld_tx/");
  Sha256.init();
  SPI.begin();
  radio.begin();
  network.begin(/*channel*/ 90, /*node address*/ this_node);
  SignedNetworkBegin();
}

void loop() {
  network.update();                          // Check the network regularlys
  SignedNetworkUpdate();
  unsigned long now = millis();              // If it's time to send a message, send it!
  if ( now - last_sent >= interval  ) {
    last_sent = now;
    Serial.print("Main loop: Sending...");
    payload_s payload;
    payload.sensor_id=123;
    payload.sensor_data=345;
    BufferListAdd(other_node, &payload);
  }

  while (UnsignedNetworkAvailable()) {
    
  }
}



