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

#include <RF24Network.h>
#include <RF24.h>
#include <SPI.h>

#include "sha256.h"
Sha256Class Sha256;

RF24 radio(9, 10);                // nRF24L01(+) radio attached using Getting Started board
RF24Network network(radio);      // Network uses that radio

const uint16_t this_node = 00;    // Address of our node in Octal format ( 04,031, etc)
const uint16_t other_node = 01;   // Address of the other node in Octal format

#include "RF24Signing.h"

RF24NetworkHeader header;



int sensor_id;
int sensor_data;

void setup(void) {
  Serial.begin(115200);
  Serial.println("RF24Network/examples/helloworld_rx/");

  SPI.begin();
  radio.begin();
  network.begin(/*channel*/ 90, /*node address*/ this_node);
}

void loop(void) {
  network.update();                  // Check the network regularly
  SignedNetworkMaintenance();

  while (UnsignedNetworkAvailable(&sensor_id, &sensor_data)) {
    Serial.print("Unsigned Sensor ID: ");
    Serial.println(sensor_id);
    Serial.print("Unsigned Sensor DATA: ");
    Serial.println(sensor_data);
  }
}
