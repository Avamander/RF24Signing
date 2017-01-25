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

const unsigned long interval = 1500;//ms  // How often to send 'hello world to the other unit

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
  mesh.setNodeID(0);
  mesh.begin();
  SignedNetworkBegin();
}

unsigned long int displayTimer;

void loop() {
  mesh.update();                          // Check the network regularly
  mesh.DHCP();
  SignedNetworkUpdate();
  unsigned long now = millis();              // If it's time to send a message, send it!
  if ( now - last_sent >= interval  ) {
    last_sent = now;
    Serial.print("Main loop: Sending...");
    payload_s payload;
    payload.sensor_id=123;
    payload.sensor_data=345;
    BufferListAdd(1, &payload, sizeof(payload_s));
  }

  if(millis() - displayTimer > 5000){
    displayTimer = millis();
    Serial.println(" ");
    Serial.println(F("********Assigned Addresses********"));
     for(int i=0; i<mesh.addrListTop; i++){
       Serial.print("NodeID: ");
       Serial.print(mesh.addrList[i].nodeID);
       Serial.print(" RF24Network Address: 0");
       Serial.println(mesh.addrList[i].address,OCT);
     }
    Serial.println(F("**********************************"));
  }
}



