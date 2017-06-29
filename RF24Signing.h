/*
    A transparent signing library for RF24Mesh
    Copyright (C) 2016 Avamander <avamander@gmail.com>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 3 of the License.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

struct SentNonce {
  uint8_t toNodeID = 255;
  uint32_t nonce = 0;
  SentNonce * next = 0;
};
SentNonce * sent_noncelist_first = 0;

struct ReceivedNonce {
  uint8_t fromNodeId = 255;
  uint32_t nonce = 0;
  uint32_t receivedTimestamp = 0;
  ReceivedNonce * next = 0;
};

ReceivedNonce * received_noncelist_first = 0;

struct PayloadMetadata { //To calculate the size more easily
  uint8_t hash[32] = {0};
  uint8_t payload_size = 0;
};

struct BufferListItem { //Buffer list item
  uint8_t hash[32] = {0};
  uint8_t payload_size = 0;
  uint8_t BufferListItemForNode = 0;
  BufferListItem * next = 0;
  void * payload = 0;
};

BufferListItem * bufferlist_first = 0;

struct payload_nonce {
  uint32_t nonce = 0;
};

const uint8_t hmacs[][20] PROGMEM = {
  {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
  {0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
};

#include "sha256.h"
Sha256Class Sha256;

extern RF24Network network;
extern RF24Mesh mesh;

/*
  Hashing related functions
*/
void hash_data(void * payload, size_t payload_size) {
  for (uint8_t i = 0; i < payload_size; i++) { //Read the payload from the
    uint8_t tempdata = 0;
    memmove(tempdata, ((uint8_t)payload) + i, 1); //Increment pointer and copy
    Serial.print(F("Writing..."));                         //the payload byte by byte to the crypto
    Serial.print(i);
    Serial.print(F(" "));
    Serial.print((char) tempdata);
    Sha256.write(tempdata);
  }
  Serial.println();
}
void hash_store(uint8_t * hash, uint8_t * result_hash) {
  memmove(result_hash, hash, sizeof(uint8_t) * 32);
}

void hash_print(uint8_t * hash) {
  for (int i = 0; i < 32; i++) {
    Serial.print("0123456789abcdef"[hash[i] >> 4]);
    Serial.print("0123456789abcdef"[hash[i] & 0xf]);
  }
  Serial.println();
}

//

bool sent_noncelist_initialize() {
  Serial.print(F("Sent nonce list init: "));
  Serial.println(sizeof(SentNonce));
  size_t size = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(void *);
  Serial.println(size);
  sent_noncelist_first = malloc(size);
  Serial.println(F("Malloc'd"));
  Serial.println((uint8_t) sent_noncelist_first);
  if (sent_noncelist_first == 0) {
    return false;
  }
  Serial.println(F("Returning true"));
  //delay(5000);
  return true;
}

bool received_noncelist_initialize() {
  Serial.print(F("Received nonce list init: "));
  Serial.println(sizeof(ReceivedNonce));
  size_t size = sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint32_t) + sizeof(void *);
  Serial.println(size);
  received_noncelist_first = malloc(size);
  Serial.println(F("Malloc'd"));
  Serial.println((uint8_t) received_noncelist_first);
  if (received_noncelist_first == 0) {
    return false;
  }

  Serial.println(F("Setting next to 0"));
  received_noncelist_first->next = 0;
  return true;
}

bool bufferlist_initialize() {
  bufferlist_first = malloc(sizeof(BufferListItem));
  Serial.println((uint8_t) bufferlist_first);
  if (bufferlist_first == 0) {
    return false;
  }

  bufferlist_first->next = 0;
  return true;
}

//

SentNonce * sent_noncelist_find_from_ID(uint8_t nodeID) {
  SentNonce * current = sent_noncelist_first;
  while (current->next != 0) {
    current = current->next;
    if (current->toNodeID == nodeID) {
      return current;
    }
  }

  return NULL;
}

bool sent_noncelist_add(uint8_t toNodeID, uint32_t nonce) {
  SentNonce * current = sent_noncelist_first;
  Serial.println(F("Finding last in list"));
//  delay(100);
  if (sent_noncelist_first == 0) {
    Serial.println(F("Current == 0"));
    sent_noncelist_initialize();
    Serial.println(F("Initialized"));
    if (sent_noncelist_first == 0) {
      Serial.print(F("Init failed"));
      return false;
    }
    Serial.println(F("Writing to allocated space"));
    //SentNonce currentnonce = * sent_noncelist_first;
    //current
    sent_noncelist_first->toNodeID = toNodeID;
    Serial.println(F("nodeID"));
    sent_noncelist_first->nonce = nonce;
    Serial.println(F("next"));
    sent_noncelist_first->next = 0;
    //currentnonce.next = 0;
    Serial.println(F("Data stored"));
    return true;
  } else {
    Serial.print(F("Starting"));
    while (current->next != 0) {
      current = current->next;
    }

    Serial.println(F("Allocating"));
    Serial.println((char) current->next);

    current->next = calloc(1, sizeof(SentNonce));
    if (current->next == 0) {
      return false;
    }
    Serial.println(F("Allocated"));
    current->next->toNodeID = toNodeID;
    current->next->nonce = nonce;
    current->next->next = 0;
    Serial.println(F("Data stored"));
  }
  return true;
}

void sent_noncelist_remove(SentNonce * previous, SentNonce * current) {
  Serial.println(F("Removing nonce"));
  Serial.println(F("Current:"));
  Serial.print(F("Nonce: "));
  Serial.println(current->nonce);
  Serial.print(F("Millis: "));
  Serial.print(millis());
  Serial.print(F(" This: "));
  Serial.println((uint8_t) current);
  Serial.print(F("Previous: "));
  Serial.println((uint8_t) previous);
  Serial.print(F("Next: "));
  Serial.println((uint8_t) current->next);
  previous->next = current->next;
  free(current);
  Serial.println(F("Removed nonce"));
}

void sent_noncelist_remove_timeout() {
  SentNonce * current = sent_noncelist_first;
  SentNonce * previous = 0;
  while (current->next != 0 && current != 0) {
    previous = current;
    current = current->next;
    if (millis() - current->nonce > 5000) {
      Serial.println(F("Found outdated nonce"));
      sent_noncelist_remove(previous, current);
    }
  }
}

void sent_noncelist_print() {
  SentNonce * current = sent_noncelist_first;
  Serial.println(F("___ SENT NONCE DUMP ___"));
  while (current->next != 0 && current != 0) {
    current = current->next;
    Serial.print(F("To: "));
    Serial.println(current->toNodeID);
    Serial.print(F("Nonce: "));
    Serial.println(current->nonce);
  }
}

/*
  Received nonce linked list functions
*/

void bufferlist_print() {
  Serial.println(F("___ BUFFER DUMP ___"));
  BufferListItem * current = bufferlist_first;
  while (current->next != 0  && current != 0) {
    Serial.print(F("For: "));
    Serial.println(current->BufferListItemForNode);
    Serial.print(F("Pointer to next: "));
    Serial.println((uint16_t) current->next);
    Serial.print(F("Hash: "));
    hash_print(current->hash);
    Serial.print(F("Payload size: "));
    Serial.println(current->payload_size);
    current = current->next;
  }

  if(current->next == 0 && current != 0){
    Serial.print(F("For: "));
    Serial.println(current->BufferListItemForNode);
    Serial.print(F("Pointer to next: "));
    Serial.println((uint16_t) current->next);
    Serial.print(F("Hash: "));
    hash_print(current->hash);
    Serial.print(F("Payload size: "));
    Serial.println(current->payload_size);
  }
}

ReceivedNonce * received_noncelist_find_from_ID(uint8_t nodeID) {
  Serial.print(F("Received nonce list find for: "));
  Serial.println(nodeID);
  ReceivedNonce * current = received_noncelist_first;
  while (current->next != 0) {
    current = current->next;
    if (current->fromNodeId == nodeID) {
      Serial.println(F("Found nonce"));
      return current;
    }
  }
  Serial.println(F("Found no nonce"));
  return 0;
}

bool received_noncelist_add(uint8_t passed_fromNodeId, uint32_t passed_nonce) {
  Serial.println(F("Received nonce list add"));
  ReceivedNonce * current = received_noncelist_first;
  Serial.println(F("Received nonce preparing"));
  if (current == 0) {
    if (!received_noncelist_initialize()) {
      return false;
    }

    Serial.println(F("Received nonce list prepared"));
    received_noncelist_first->fromNodeId = passed_fromNodeId;
    received_noncelist_first->nonce = passed_nonce;
    received_noncelist_first->receivedTimestamp = millis();
    received_noncelist_first->next = 0;
    Serial.println(F("Done."));
  } else {
      Serial.println(F("Searching for nonce list last"));
    while (current->next != 0) {
      current = current->next;
    }

    current->next = calloc(1, sizeof(ReceivedNonce));
    if (current->next == 0) {
      return false;
    }
    current->next->fromNodeId = passed_fromNodeId;
    current->next->nonce = passed_nonce;
    current->next->receivedTimestamp = millis();
    current->next->next = 0;
    return true;
  }
}

void received_noncelist_remove(ReceivedNonce * previous, ReceivedNonce * current) {
  Serial.print(F("Received nonce list remove"));
  previous->next = current->next;
  free(current);
}

void received_noncelist_remove_timeout() {
  ReceivedNonce * current = received_noncelist_first;
  ReceivedNonce * previous = 0;
  while (current->next != 0 && current != 0) {
    previous = current;
    current = current->next;
    if (millis() - current->receivedTimestamp > 5000) {
      Serial.print(F("Received nonce timeout"));
      received_noncelist_remove(previous, current);
    }
  }
}

void received_noncelist_print() {
  ReceivedNonce * current = received_noncelist_first;
  Serial.println(F("___ RECIVED NONCE DUMP ___"));
  while (current->next != 0  && current != 0) {
    current = current->next;
    Serial.print(F("To: "));
    Serial.println(current->fromNodeId);
    Serial.print(F("Nonce: "));
    Serial.println(current->nonce);
    Serial.print(F("Timestamp: "));
    Serial.println(current->receivedTimestamp);
  }
}

void bufferlist_remove(BufferListItem * previous, BufferListItem * current) {
  Serial.println(F("Removing from buffer list"));
  if (current->next == 0) {
    Serial.println(F("Next is null"));
  } else {
    Serial.println(F("Next is not null, clearing"));
    previous->next = current->next;
  }

  free(current->payload);
  free(current);
}

void request_nonce_from_node_id(uint8_t nodeID) {
  payload_nonce nonce_payload;
  nonce_payload.nonce = 0;
  Serial.print(F("Requesting nonce from: "));
  Serial.println(nodeID);
  uint8_t status = mesh.write(&nonce_payload, 'R', 1, nodeID);
  Serial.print(F("Status: "));
  Serial.println(status);
}
/*
  Sending buffer related functions
*/
BufferListItem * bufferlist_find_for_id(uint8_t nodeID) {
  BufferListItem * current = bufferlist_first;
  while (current->next != 0) {
    current = current->next;
    if (current->BufferListItemForNode == nodeID) {
      return current;
    }
  }

  return NULL;
}

bool bufferlist_send(BufferListItem * item, ReceivedNonce * nonce, BufferListItem * previousitem) {
  Serial.println(F("Sending buffer item"));
  size_t buf_size = sizeof(PayloadMetadata) + item->payload_size; //Calculate the size of the message
  void * buf = calloc(1, buf_size); //Allocate enough memory for the buffer
  Serial.print(F("Metadata size: "));
  Serial.println((uint8_t) sizeof(PayloadMetadata));
  Serial.print(F("Payload size: "));
  Serial.println((uint8_t) item->payload_size);
  Serial.print(F("Buffer size: "));
  Serial.println((uint8_t) buf_size);
  Serial.print(F("Buffer address: "));
  Serial.println((uint8_t) buf);

  Sha256.initHmac(hmacs[item->BufferListItemForNode], 20); //Initialize the hmac
  hash_data(item->payload, item->payload_size); //Hash the data itself
  hash_store(Sha256.result(), item->hash); //Store hash in payload hash

  Serial.print(F("Memmove 1: "));
  Serial.println((uint8_t) memmove(buf, item, sizeof(PayloadMetadata))); //Copy metadata to the start of the buffer
  Serial.print(F("Memmove 2: "));
  Serial.println((uint8_t) memmove(buf + sizeof(PayloadMetadata), item->payload, item->payload_size)); //Copy the payload to the end of the buffer

  Serial.println(F("Buffer item prepared."));
  bool state = mesh.write(buf, 'S', buf_size, item->BufferListItemForNode); //Send the message
  Serial.print(F("I guess it's "));
  Serial.println(state ? F("sent") : F("not sent"));
  if (state) { //Remove if sent
    Serial.println(F("Removing sent message"));
    bufferlist_remove(previousitem, item);
  }
  Serial.println(F("Buffer list"));
  bufferlist_print();
  Serial.println(F("Buffer list printed"));
}


bool BufferListAdd(uint8_t BufferListItemForNode, void * payload, uint8_t size) {
  Serial.println(F("Add item to buffer list"));
  BufferListItem * current = bufferlist_first;
  if (bufferlist_first == 0) {
    if (!bufferlist_initialize()) {
      return false;
    }
    current = bufferlist_first;  //Otherwise it's going to be null
    current->BufferListItemForNode = BufferListItemForNode;
    current->payload = payload;
    Serial.print(F("Size: "));
    Serial.println(size);
    current->payload_size = size;
  } else {
    while (current->next != 0) {  //Take the last item in the list
      Serial.println(F("Finding the last item"));
      current = current->next;
    }

    current->next = calloc(1, sizeof(ReceivedNonce));
    if (current->next == 0) {
      return false;
    }

    current->next->BufferListItemForNode = BufferListItemForNode;
    current->next->payload = payload;
    current->next->payload_size = size;
  }

  Serial.println(F("Finding nonce for nodeID"));
  ReceivedNonce * nonce = received_noncelist_find_from_ID(BufferListItemForNode);
  if (nonce != 0) {
    //bufferlist_send(current->next, nonce, current);
    return true;
  } else {
    Serial.println(F("Requested nonce"));
    request_nonce_from_node_id(BufferListItemForNode);
    Serial.println(F("Requested"));
  }
  Serial.println(F("Added item to buffer list"));
  return true;
}

void bufferlist_send_all() {
  BufferListItem * current = bufferlist_first;
  bufferlist_print();
  if(bufferlist_first != 0 && bufferlist_first->next == 0){
      Serial.println(F("There's something in the buffer to send"));
      uint32_t nonce = received_noncelist_find_from_ID(current->BufferListItemForNode);
    
      if (nonce != 0) {
        Serial.println(F(" ..one nonce for node is not 0!"));
        bufferlist_send(current->next, nonce, current);
      }
      current = current->next;
  } else{
    while (current->next != 0  && current != 0) {
      Serial.println(F("There's something in the buffer to send"));
      uint32_t nonce = received_noncelist_find_from_ID(current->BufferListItemForNode);
    
      if (nonce != 0) {
        Serial.println(F(" ..one nonce for node is not 0!"));
        bufferlist_send(current->next, nonce, current);
      }
      current = current->next;
    }
  }
}

/*  //TODO: Payloads should be dumped at one point
  void bufferlist_removeTimeout(BufferListItem * start) {
    BufferListItem * current = start;
    BufferListItem * previous = NULL;
    while (current->next != NULL) {
        previous = current;
        current = current->next;
        if(millis() - current->receivedTimestamp > 5000){
            received_noncelist_remove(previous, current);
        }
    }
  }*/

/*
  Intercepting signing payloads
*/
bool UnsignedNetworkAvailable(void) {
  //Serial.println(F(","));
  if (network.available()) {
    Serial.print(F("NETWORK RECEIVE: "));
    RF24NetworkHeader header;
    network.peek(header);
    Serial.println((char)header.type);
    switch (header.type) { // Is there anything ready for us?
      case 'S': { //"S" like "you sent me something signed"
          Serial.print(F("S Time: "));
          Serial.println(millis());
          PayloadMetadata payload;
          Serial.println(F("Reading data..."));
          network.peek(header, &payload, sizeof(payload));
          uint16_t nodeID = mesh.getNodeID(header.from_node);
          Serial.print(F(" message from: "));
          Serial.println(nodeID);
          Sha256.initHmac(hmacs[nodeID], 20);

          Serial.println(F("Writing payload to crypto buffer..."));
          void * buf = calloc(1, payload.payload_size);
          network.peek(header, buf, sizeof(PayloadMetadata) + payload.payload_size);
          hash_data(buf, payload.payload_size);
          Serial.println(F("Wrote to crypto buffer"));
          free(buf);

          uint32_t tempnonce = received_noncelist_find_from_ID(nodeID);
          if (tempnonce != 0) {
            Serial.print(F("Nonce found: "));
            Serial.println(tempnonce);
            Sha256.write(tempnonce);
          } else {
            Serial.println(F("Nonce not found!"));
            return false; //WARNING: Just discarding the message
          }
          uint8_t calculated_hash[32];
          hash_store(Sha256.resultHmac(), calculated_hash);
          Serial.print(F("Calculated hash: "));
          hash_print(calculated_hash);
          Serial.print(F("Received hash: "));
          hash_print(payload.hash);
          if (calculated_hash == payload.hash) {
            Serial.println(F("EQUAL HASH?!"));
          } else {
            Serial.println(F("Inequal hash!"));
            return false;
          }
          return true;
        }
      case 'R': { //"R" like "send me a nonce"
          Serial.print(F("R Time: "));
          Serial.println(millis());


          payload_nonce payload;
          RF24NetworkHeader received_header;

          network.read(received_header, &payload, sizeof(payload_nonce));  //We just wanted to know the type of the message, discard the content
          uint32_t time = millis();
          payload.nonce = time;
          Serial.print(F("Sent nonce: "));
          Serial.println(payload.nonce);
          Serial.print(F("To node: "));
          uint16_t nodeID = mesh.getNodeID(received_header.from_node);
          Serial.println(nodeID);
          Serial.println(F("Switch"));
          sent_noncelist_add(nodeID, time);
          Serial.println(F("Nonce stored"));
          mesh.write(&payload, 'N', sizeof(payload), nodeID);
          Serial.println(F("Completed nonce sending"));
          sent_noncelist_print();
          return false;
        }
      case 'N': { //"N" like "you sent me a nonce"
          struct payload_no {
            uint32_t nonce;
          };

          Serial.print(F("N Time: "));
          Serial.println(millis());

          payload_no payload_nonce;
          RF24NetworkHeader header;

          network.read(header, &payload_nonce, sizeof(payload_nonce));
          Serial.print(F("Recived nonce: "));
          Serial.println(payload_nonce.nonce);
          Serial.print(F("From node: "));
          uint16_t nodeID = mesh.getNodeID(header.from_node);
          Serial.println(nodeID);
          received_noncelist_add(nodeID, payload_nonce.nonce);
          return false;
        }
      default: {
          Serial.print(F("Received message with type '"));
          Serial.print(header.type);
          Serial.println(F("'"));
          return true;
        }
    }
  }
  return false;
}

/*
  Signed network maintenance
*/
uint32_t bufferListMaintenanceTimer = 0;
uint32_t bufferListRetryTimer = 0;
void signed_network_update() {
  //Serial.print(F("."));
  //Serial.println(F("Mesh update"));
  mesh.update();                          // Check the network...
  //Serial.println(F("d"));

  if (millis() - bufferListMaintenanceTimer > 500) {
    Serial.println(F("Maintenance"));
    if (received_noncelist_first != 0) { // TODO: This comparison is probably faster than the millis(), sub. and comparison
      Serial.println(F("Checking for received timeouts"));
      received_noncelist_remove_timeout();
    }

    if (sent_noncelist_first != 0) {
      Serial.println(F("Checking for sent timeouts"));
      sent_noncelist_remove_timeout();
    }

    if (bufferlist_first != 0) {
      Serial.println(F("Sending all"));
      bufferlist_send_all();
    }
    bufferListMaintenanceTimer = millis();
  }

  mesh.update();                          // ...and again...
  //Serial.println(F("d"));
  if (millis() - bufferListRetryTimer > 1000) {
    if (bufferlist_first != 0) {
      Serial.println(F("Retrying all"));
      bufferlist_send_all();
      //BufferListReRequestNonces();
    }
    bufferListRetryTimer = millis();
  }

  mesh.update();
  //Serial.println(F("d"));
}

void signed_network_begin() {
}