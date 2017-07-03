
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
#include <RF24Mesh.h>
#include <RF24Network.h>
#include <RF24.h>
#include <SPI.h>


RF24 radio(9, 10);
RF24Network network(radio);   // Network uses that radio
RF24Mesh mesh(radio, network);

const unsigned long interval = 5000;//ms  // How often to send 'hello world to the other unit

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

struct payload_crap {
  uint32_t shit[32] = {1};
};

struct payload_crap crap;
struct payload_s payload;

unsigned long displayTimer = 0;

void setup(void) {
  delay(1000);
  Serial.begin(115200);
  Serial.println("RF24Network/examples/helloworld_tx/");
  mesh.setNodeID(0);
  Serial.println(F("RF24Mesh 1/2 ready"));
  mesh.begin();
  Serial.println(F("RF24Mesh ready"));
  signed_network_begin();
  Serial.println(F("RF24Signing ready"));
}

void loop() {
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
        payload.sensor_id = 123;
        payload.sensor_data = 345;
        bufferlist_add(1, &payload, sizeof(payload_s));
        Serial.println(F("Returned to switch"));
        break;
      case 'e':
        displayTimer = millis();
        Serial.println(F(" "));
        Serial.println(F("********Assigned Addresses********"));
        for (int i = 0; i < mesh.addrListTop; i++) {
          Serial.print(F("NodeID: "));
          Serial.print(mesh.addrList[i].nodeID);
          Serial.print(F(" RF24Network Address: 0"));
          Serial.println(mesh.addrList[i].address, OCT);
        }
        Serial.println(F("**********************************"));
        Serial.println(F(" "));
        break;
      case 'f':
        payload_s payload_simple;
        payload_simple.sensor_id = 123;
        payload_simple.sensor_data = 234;
        mesh.write(&payload_simple, (uint8_t)'T', (size_t)sizeof(payload_s), (uint8_t)1);
        break;
      case 'g':
        Serial.println(sizeof(payload_crap));
        mesh.write(&crap, (uint8_t)'T', (size_t)sizeof(payload_s), (uint8_t)1);
        break;
      case 'h':
        delay(1000);
        break;
      case 'i':
        requested_noncelist_print();
      default:
        break;
    }
  }

  //Serial.println(F("DHCP"));
  mesh.DHCP();
  //Serial.println(F("Update"));
  signed_network_update();
  //Serial.println(F("DHCP"));
  mesh.DHCP();
  //Serial.println(F("DHCP done"));

  if (millis() - displayTimer > 1000) {
    Serial.println(millis());
    displayTimer = millis();
  }

  while (UnsignedNetworkAvailable()) {
    Serial.println(F("-"));
    RF24NetworkHeader header;
    network.peek(header);
    Serial.println(F("<"));
    uint32_t dat = 0;
    switch (header.type) {
      // Display the incoming millis() values from the sensor nodes
      case 'M': Serial.println(F(">")); network.read(header, &dat, sizeof(dat)); Serial.println(dat); break;
      default: Serial.println(F("|")); network.read(header, 0, 0); Serial.println(header.type); break;
    }
  }
}



