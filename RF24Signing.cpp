/*
    A transparent signing library for RF24Mesh
    Copyright (C) 2017 Avamander <avamander@gmail.com>

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


#include "RF24Signing.h"

static RF24Signing_ rfsigned;

#include "hmacs.c"

void RF24Signing_signed_network_begin(uint8_t passed_nodeID) {
  Serial.println(F("Signed network begun"));
  Serial.println((uint8_t)&rfsigned.current_node_ID);
  rfsigned.current_node_ID = passed_nodeID;
}

/*
  Hashing related functions
*/
void RF24Signing_hash_data(void * payload, size_t payload_size) {
  Serial.println((uint8_t) payload);
  Serial.println(payload_size);
  for (uint8_t i = 0; i < payload_size; i++) { //Read the payload from the
    Serial.print(F("Writing... "));            //the payload byte by byte to the crypto
    uint8_t * pload = (uint8_t*) payload;
    uint8_t * pload_shifted = pload + i;
    Serial.print((uint8_t) *pload_shifted, DEC);
    Serial.print(F(" "));
    rfsigned.Sha256.write(*pload_shifted);
  }
  Serial.println();
}

void RF24Signing_hash_print(uint8_t * hash) {
  for (uint8_t i = 0; i < 32; i++) {
    Serial.print(hash[i]);
  }
  Serial.println();
}

void RF24Signing_hash_store(void * hash, void * result_hash) {
  memmove(result_hash, hash, sizeof(uint8_t[32]));
}

bool RF24Signing_hash_compare(void * hash1, void * hash2) {
  for (uint8_t byte = 0; byte < 32; byte++) {
    if (*(((uint8_t *)hash1) + byte) != *(((uint8_t *)hash2) + byte)) {
      return false;
    }
  }
  return true;
}

void RF24Signing_requested_noncelist_print() {
  RequestedNonce * current = rfsigned.requested_noncelist_first;
  Serial.println(F("___ REQUESTED NONCE LIST DUMP ___"));
  while (current != 0) {
    Serial.print(F("Requested this: "));
    Serial.println((uint8_t)current);
    Serial.print(F("Requested from: "));
    Serial.println(current->fromNodeId);
    Serial.print(F("Requested time: "));
    Serial.println(current->time);
    Serial.print(F("Requested last: "));
    Serial.println(current->lastrequest);
    Serial.print(F("Requested next: "));
    Serial.println((uint8_t) current->next);
    current = current->next;
  }
}

void RF24Signing_sent_noncelist_print() {
  Serial.println(F("___ SENT NONCE DUMP ___"));

  SentNonce * current = rfsigned.sent_noncelist_first;
  while (current != 0) {
    Serial.print(F("To: "));
    Serial.println(current->toNodeID);
    Serial.print(F("Nonce: "));
    Serial.println(current->nonce);
    current = current->next;
  }
}

void RF24Signing_bufferlist_print() {
  Serial.println(F("___ BUFFER DUMP ___"));

  BufferListItem * current = rfsigned.bufferlist_first;
  while (current != 0) {
    Serial.print(F("For: "));
    Serial.println(current->BufferListItemForNode);
    Serial.print(F("Pointer to next: "));
    Serial.println((uint16_t) current->next);
    Serial.print(F("Hash: "));
    RF24Signing_hash_print(current->hash);
    Serial.print(F("Payload size: "));
    Serial.println(current->payload_size);
    current = current->next;
  }
}

void RF24Signing_received_noncelist_print() {
  ReceivedNonce * current = rfsigned.received_noncelist_first;
  Serial.println(F("___ RECEIVED NONCE DUMP ___"));
  while (current != 0) {
    Serial.print(F("To: "));
    Serial.println(current->fromNodeId);
    Serial.print(F("Nonce: "));
    Serial.println(current->nonce);
    Serial.print(F("Timestamp: "));
    Serial.println(current->receivedTimestamp);
    current = current->next;

  }
}

void RF24Signing_random_data_print(void * data, size_t size) {
  void * start = data;

  for (uint8_t offset = 0; offset < size; offset++) {
    Serial.print((uint8_t)(*((uint8_t *)(data + offset))));
    Serial.print(F(" "));
  }
  Serial.println(F(" "));
}

bool RF24Signing_sent_noncelist_initialize() {
  Serial.print(F("Sent nonce list init: "));
  Serial.println(sizeof(SentNonce));

  rfsigned.sent_noncelist_first = malloc(sizeof(SentNonce));
  Serial.println(F("Malloc'd"));
  Serial.println((uint8_t) rfsigned.sent_noncelist_first);
  if (rfsigned.sent_noncelist_first == 0) {
    return false;
  }
  Serial.println(F("Returning true"));
  return true;
}

bool RF24Signing_received_noncelist_initialize() {
  Serial.print(F("Received nonce list init: "));
  rfsigned.received_noncelist_first = malloc(sizeof(ReceivedNonce));
  Serial.println(F("Malloc'd"));
  Serial.println((uint8_t) rfsigned.received_noncelist_first);
  if (rfsigned.received_noncelist_first == 0) {
    return false;
  }

  Serial.println(F("Setting next to 0"));
  rfsigned.received_noncelist_first->next = 0;
  return true;
}

bool RF24Signing_bufferlist_initialize() {
  rfsigned.bufferlist_first = malloc(sizeof(BufferListItem));
  Serial.println((uint8_t) rfsigned.bufferlist_first);
  if (rfsigned.bufferlist_first == 0) {
    Serial.println(F("Buffer init failed"));
    return false;
  }

  rfsigned.bufferlist_first->next = 0;
  return true;
}

bool RF24Signing_requested_noncelist_initialize() {
  rfsigned.requested_noncelist_first = malloc(sizeof(RequestedNonce));
  Serial.println((uint8_t) rfsigned.requested_noncelist_first);
  if (rfsigned.requested_noncelist_first == 0) {
    Serial.println(F("Request list init failed"));
    return false;
  }

  rfsigned.requested_noncelist_first->next = 0;
  return true;
}

void RF24Signing_request_nonce_from_node_id(uint8_t nodeID) {
  payload_nonce nonce_payload;
  nonce_payload.nonce = 0;
  Serial.print(F("Requesting nonce from: "));
  Serial.println(nodeID);
  uint8_t status = mesh.write(&nonce_payload, 'R', 1, nodeID);
  Serial.print(F("Status: "));
  Serial.println(status);
}

bool RF24Signing_requested_noncelist_add(uint8_t passed_nodeID) {
  Serial.println(F("Adding to requested noncelist"));
  RequestedNonce * current = rfsigned.requested_noncelist_first;
  if (current == 0) {
    Serial.println(F("Not initialized"));
    if (!RF24Signing_requested_noncelist_initialize()) {
      return false;
    }
    current = rfsigned.requested_noncelist_first;
  } else {
    while (current->next != 0) {
      Serial.println(F("Looking for the last"));
      current = current->next;
    }
  }
  Serial.println(F("Storing data"));
  current->fromNodeId = passed_nodeID;
  current->time = millis();
  RF24Signing_request_nonce_from_node_id(passed_nodeID);
  current->lastrequest = millis();
  Serial.println(F("Stored"));
  RF24Signing_requested_noncelist_print();
}

bool RF24Signing_requested_noncelist_delete(RequestedNonce * previous, RequestedNonce * current) {
  //Delete list item
  if (previous == 0) {
    Serial.println(F("Removing first nonce request"));
    free(current);
    rfsigned.requested_noncelist_first = 0;
    RF24Signing_bufferlist_print();
  } else {
    Serial.println(F("Removing a nonce request in the middle"));
    previous->next = current->next;
    free(current);
  }
}

bool RF24Signing_requested_noncelist_received(uint8_t passed_nodeID) {
  RequestedNonce * current = rfsigned.requested_noncelist_first;
  RequestedNonce * previous = 0;
  RF24Signing_requested_noncelist_print();
  while (current != 0) {
    if (current->fromNodeId == passed_nodeID) {
      Serial.println(F("Deleting request"));
      RF24Signing_requested_noncelist_delete(previous, current);
    }
    RF24Signing_requested_noncelist_print();
    previous = current;
    current = current->next;
  }
}

RequestedNonce * RF24Signing_requested_noncelist_find_for_nodeID(uint8_t passed_nodeID) {
  //Find if request exists for nodeID
  RequestedNonce * current = rfsigned.requested_noncelist_first;
  while (current != 0) {
    if (current->fromNodeId == passed_nodeID) {
      return current;
    }
    current = current->next;
  }
  return 0;
}

bool RF24Signing_requested_noncelist_retry_all() {
  RequestedNonce * previous = 0;
  RequestedNonce * current = rfsigned.requested_noncelist_first;
  RF24Signing_requested_noncelist_print();
  while (current != 0) {
    Serial.println(F("Request list is not 0"));
    Serial.println(current->lastrequest);
    if (millis() - current->lastrequest > 2000) {
      Serial.println(F("Rerequesting nonce"));
      RF24Signing_request_nonce_from_node_id(current->fromNodeId);
      current->lastrequest = millis();
    }
    previous = current;
    current = current->next;
  }
}

bool RF24Signing_requested_noncelist_remove_timeout() {
  RequestedNonce * current = rfsigned.requested_noncelist_first;
  RequestedNonce * previous = 0;
  while (current != 0) {
    if (millis() - current->time > 10000) {
      Serial.println(F("Removing nonce request"));
      RF24Signing_requested_noncelist_delete(previous, current); //deletes current
    }
    previous = current;
    current = current->next;

  }
  return 0;
}


//

SentNonce * RF24Signing_sent_noncelist_find_from_ID(uint8_t nodeID) {
  SentNonce * current = rfsigned.sent_noncelist_first;
  while (current != 0) {
    Serial.println(F("Sent noncelist find"));
    if (current->toNodeID == nodeID) {
      Serial.print(F("Found for: "));
      Serial.println(nodeID);
      return current;
    }
    current = current->next;

  }

  return 0;
}

bool RF24Signing_sent_noncelist_add(uint8_t toNodeID, uint32_t nonce) {
  SentNonce * current = rfsigned.sent_noncelist_first;
  Serial.println(F("Finding last in list"));
  //delay(100);
  Serial.println(F("Starting"));
  if (current == 0) {
    Serial.println(F("Initializing"));
    if (!RF24Signing_sent_noncelist_initialize()) {
      return false;
    }
    current = rfsigned.sent_noncelist_first;
  } else {
    while (current->next != 0) {
      current = current->next;
    }

    Serial.println(F("Allocating"));
    Serial.println((char) current);

    current->next = calloc(1, sizeof(SentNonce));
    if (current->next == 0) {
      return false;
    }
    current = current->next;
  }
  Serial.println(F("Allocated"));
  current->toNodeID = toNodeID;
  current->nonce = nonce;
  current->next = 0;
  Serial.println(F("Data stored"));
  delay(1000);
  return true;
}

void RF24Signing_sent_noncelist_remove(SentNonce * previous, SentNonce * current) {
  Serial.println(F("Removing nonce"));
  Serial.println(F("Current:"));
  Serial.print(F("Nonce: "));
  Serial.println(current->nonce);
  Serial.print(F("Millis: "));
  Serial.println(millis());
  Serial.print(F("This: "));
  Serial.println((uint8_t) current);
  Serial.print(F("Previous: "));
  Serial.println((uint8_t) previous);
  Serial.print(F("Next: "));
  Serial.println((uint8_t) current->next);
  if (previous != 0) {
    previous->next = current->next;
  } else {
    rfsigned.sent_noncelist_first = 0;
  }
  free(current);
  Serial.println(F("Removed nonce"));
}

void RF24Signing_sent_noncelist_remove_timeout() {
  Serial.println(F("Removing sent timeout"));
  SentNonce * current = rfsigned.sent_noncelist_first;
  SentNonce * previous = 0;
  while (current != 0) {
    if (millis() - current->nonce > 5000) {
      Serial.println(F("Found outdated nonce"));
      RF24Signing_sent_noncelist_remove(previous, current);
    }

    previous = current;
    current = current->next;


  }
}

ReceivedNonce * RF24Signing_received_noncelist_find_from_ID(uint8_t nodeID) {
  Serial.print(F("Received nonce list find for: "));
  Serial.println(nodeID);
  ReceivedNonce * current = rfsigned.received_noncelist_first;
  while (current != 0) {
    if (current->fromNodeId == nodeID) {
      Serial.print(F("Found nonce: "));
      Serial.println(current->nonce);
      return current;
    }
    current = current->next;

  }
  Serial.println(F("Found no nonce"));
  return 0;
}

bool RF24Signing_received_noncelist_add(uint8_t passed_fromNodeId, uint32_t passed_nonce) {
  Serial.println(F("Received nonce list add"));
  ReceivedNonce * current = rfsigned.received_noncelist_first;
  Serial.println(F("Received nonce preparing"));
  Serial.println(F("Searching for nonce list last"));
  RF24Signing_received_noncelist_print();

  if (current == 0) {
    if (!RF24Signing_received_noncelist_initialize()) {
      return false;
    }
    current = rfsigned.received_noncelist_first;
  } else {
    while (current->next != 0) {
      current = current->next;
    }
    current->next = malloc(sizeof(ReceivedNonce));
    current = current->next;
    if (current == 0) {
      return false;
    }
  }

  current->fromNodeId = passed_fromNodeId;
  current->nonce = passed_nonce;
  current->receivedTimestamp = millis();
  current->next = 0;
  RF24Signing_received_noncelist_print();
  RF24Signing_requested_noncelist_received(passed_fromNodeId);
  return true;
}

void RF24Signing_received_noncelist_remove(ReceivedNonce * previous, ReceivedNonce * current) {
  Serial.println(F("Received nonce list remove"));
  RF24Signing_received_noncelist_print();
  if (previous == 0) {
    free(current);
    rfsigned.received_noncelist_first = 0;
  } else {
    previous->next = current->next;
    free(current);
  }
  RF24Signing_received_noncelist_print();
}

void RF24Signing_received_noncelist_remove_timeout() {
  ReceivedNonce * current = rfsigned.received_noncelist_first;
  ReceivedNonce * previous = 0;
  while (current != 0) {
    Serial.println(F("First not empty"));
    RF24Signing_received_noncelist_print();
    if (millis() - current->receivedTimestamp > 5000) {
      Serial.println(F("Received nonce timeout: "));
      Serial.println(current->receivedTimestamp);
      RF24Signing_received_noncelist_remove(previous, current);
    }
    previous = current;
    current = current->next;
    RF24Signing_received_noncelist_print();
  }
}

void RF24Signing_bufferlist_remove(BufferListItem * previous, BufferListItem * current) {
  Serial.println(F("Removing from buffer list"));
  if (current = rfsigned.bufferlist_first) { // Start of buffer list
    free(current->payload);
    free(current);
    rfsigned.bufferlist_first = 0;
  } else if (current->next == 0) { // First in the buffer list
    free(current->payload);
    free(current);
    previous->next = 0;
  } else if (previous != 0) { // Somehwere in the middle of the list
    previous->next = current->next;
    free(current->payload);
    free(current);
  } else {
    Serial.print(F("Error case not matched, dumping pointers: "));
    Serial.print((uint8_t) rfsigned.bufferlist_first);
    Serial.print(F(" "));
    Serial.print((uint8_t) previous);
    Serial.print(F(" "));
    Serial.print((uint8_t) previous->next);
    Serial.print(F(" "));
    Serial.print((uint8_t) current);
    Serial.print(F(" "));
    Serial.println((uint8_t) current->next);
  }
}

/*
  Sending buffer related functions
*/
BufferListItem * RF24Signing_bufferlist_find_for_id(uint8_t nodeID) {
  BufferListItem * current = rfsigned.bufferlist_first;
  while (current != 0) {
    if (current->BufferListItemForNode == nodeID) {
      return current;
    }
    current = current->next;
    if (current == 0) {
      return NULL;
    }
  }

  return NULL;
}

void RF24Signing_read_hmac_from_progmem(uint8_t nodeID, void * hmac_pointer) {
  uint8_t hmac[20] = {0};
  uint8_t first_address_hmac = 20 * nodeID;
  Serial.println(nodeID);
  for (uint8_t offset = 0; offset < 20; offset++) {
    uint8_t character = pgm_read_byte_near(&(hmacs[nodeID][offset]));
    Serial.print(character);
    Serial.print(F(" "));
    memmove(((uint8_t*)&hmac) + offset, &character, 1);
  }
  memmove(hmac_pointer, hmac, sizeof(hmac));
  Serial.println();
}

bool RF24Signing_bufferlist_send(BufferListItem * item, ReceivedNonce * nonce, BufferListItem * previousitem) {
  Serial.println(F("Sending buffer item"));
  size_t sizeof_buffer = sizeof(PayloadMetadata) + item->payload_size; //Calculate the size of the message
  void * buf = malloc(sizeof_buffer); //Allocate enough memory for the buffer
  Serial.print(F("Metadata size: "));
  Serial.println((uint8_t) sizeof(PayloadMetadata));
  Serial.print(F("Payload size: "));
  Serial.println((uint8_t) item->payload_size);
  Serial.print(F("Buffer size: "));
  Serial.println((uint8_t) sizeof_buffer);
  Serial.print(F("Buffer address: "));
  Serial.println((uint8_t) buf);

  Serial.print(F("From: "));
  Serial.println(rfsigned.current_node_ID);
  Serial.print(F("To: "));
  Serial.println(item->BufferListItemForNode);

  uint8_t hmac[20] = {0};
  RF24Signing_read_hmac_from_progmem(rfsigned.current_node_ID, &hmac);
  if (hmac[0] == hmacs[0][0]) {
    Serial.println(F("Equal"));
  }

  Serial.print(F("HMAC: "));
  Serial.println(hmac[0], DEC);
  Serial.println(hmacs[0][0], DEC);
  Serial.println(hmacs[1][0], DEC);

  for (int i; i > 20; i++) {
    Serial.print(hmac[i]);
  }
  Serial.println();

  rfsigned.Sha256.initHmac(hmac, 20); //Initialize the hmac
  Serial.print(F("Size of full payload: "));
  Serial.println(item->payload_size);

  RF24Signing_hash_data(item->payload, item->payload_size); //Hash the data itself
  Serial.print(F("Nonce: "));
  Serial.println(nonce->nonce);

  RF24Signing_hash_data(&(nonce->nonce), sizeof(uint32_t));
  RF24Signing_hash_store(rfsigned.Sha256.resultHmac(), item->hash); //Store hash in payload hash

  //Serial.print(F("Memmove 1: "));
  //Serial.println((uint8_t)
  memmove(buf, item, sizeof(PayloadMetadata)); //Copy metadata to the start of the buffer

  Serial.print(F("Metadata: "));
  RF24Signing_random_data_print(buf, sizeof(PayloadMetadata));

  //Serial.print(F("Memmove 2: "));
  //Serial.println((uint8_t)
  memmove(buf + sizeof(PayloadMetadata), item->payload, item->payload_size); //Copy the payload to the end of the buffer

  Serial.print(F("Full buffer: "));
  RF24Signing_random_data_print(buf, sizeof(PayloadMetadata) + item->payload_size);

  Serial.print(F("Generated hash: "));
  RF24Signing_hash_print(item->hash);

  bool state = mesh.write(buf, 'S', sizeof_buffer, item->BufferListItemForNode); //Send the message
  Serial.print(F("I guess it's "));
  Serial.println(state ? F("sent") : F("not sent"));
  if (state) { //Remove if sent
    Serial.println(F("Removing sent message"));
    RF24Signing_bufferlist_remove(previousitem, item);
  }
  Serial.println(F("Buffer list"));
  RF24Signing_bufferlist_print();
  Serial.println(F("Buffer list printed"));
  delay(1000);
}


bool RF24Signing_bufferlist_add(uint8_t BufferListItemForNode, void * payload, uint8_t size) {
  Serial.println(F("Add item to buffer list"));
  Serial.println(size);
  BufferListItem * current = rfsigned.bufferlist_first;
  BufferListItem * previous = 0;
  if (rfsigned.bufferlist_first == 0) {
    if (!RF24Signing_bufferlist_initialize()) {
      return false;
    } else {
      current = rfsigned.bufferlist_first;
    }
  } else {
    while (current->next != 0) {  //Take the last item in the list
      Serial.println(F("Finding the last item"));
      current = current->next;
    }

    current->next = malloc(sizeof(ReceivedNonce));
    if (current->next == 0) {
      Serial.println(F("Failed to malloc"));
      return false;
    }
    previous = current;
    current = current->next;
  }

  current->BufferListItemForNode = BufferListItemForNode;
  current->payload = payload;
  current->payload_size = size;

  Serial.println(F("Finding nonce for nodeID"));
  ReceivedNonce * nonce = RF24Signing_received_noncelist_find_from_ID(BufferListItemForNode);
  if (nonce != 0) {
    RF24Signing_bufferlist_send(current, nonce, previous);
    return true;
  } else {
    Serial.println(F("Requested nonce"));
    RF24Signing_requested_noncelist_add(BufferListItemForNode);
    Serial.println(F("Requested"));
  }
  Serial.println(F("Added item to buffer list"));
  return true;
}

void RF24Signing_bufferlist_send_all() {
  BufferListItem * current = rfsigned.bufferlist_first;
  BufferListItem * previous = 0;
  RF24Signing_bufferlist_print();
  Serial.println(F("Sending all: "));
  Serial.println((uint8_t) rfsigned.bufferlist_first);
  Serial.println((uint8_t) rfsigned.bufferlist_first->next);
  while (current != 0) {
    Serial.println(F("There's something in the buffer to send"));
    uint32_t nonce = RF24Signing_received_noncelist_find_from_ID(current->BufferListItemForNode);

    if (nonce != 0) {
      Serial.println(F(" ..one nonce for node is not 0!"));
      RF24Signing_bufferlist_send(current, nonce, previous);
    }
    previous = current;
    current = current->next;
  }
}

//TODO: Payloads should be dumped at one point
/*void RF24Signing_bufferlist_remove_timeout() {
  BufferListItem * current = start;
  BufferListItem * previous = NULL;
  while (current->next != NULL) {
      if(millis() - current-> > 5000){
          RF24Signing_received_noncelist_remove(previous, current);
      }
      previous = current;
      current = current->next;
  }
  }*/

/*
  Intercepting signing payloads
*/
bool RF24Signing_unsigned_network_available(void) {
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

          network.peek(header, &payload, sizeof(PayloadMetadata));
          uint8_t nodeID = mesh.getNodeID(header.from_node);

          Serial.print(F("From: "));
          Serial.println(nodeID);
          Serial.print(F("To: "));
          Serial.println(rfsigned.current_node_ID);


          uint8_t hmac[20] = {0};
          RF24Signing_read_hmac_from_progmem(nodeID, &hmac);
          if (hmac[0] == hmacs[0][0]) {
            Serial.println(F("Equal"));
          }

          Serial.print(F("HMAC: "));
          Serial.println(hmacs[0][0], DEC);
          Serial.println(hmac[0], DEC);

          for (int i; i > 20; i++) {
            Serial.print(hmac[i]);
          }

          Serial.println();

          rfsigned.Sha256.initHmac(hmac, 20);

          Serial.print(F("Size of payload: "));
          Serial.println(payload.payload_size);

          Serial.print(F("Metadata: "));
          RF24Signing_random_data_print(&payload, sizeof(PayloadMetadata));

          size_t sizeoffullbuffer = sizeof(PayloadMetadata) + payload.payload_size;

          void * buf = malloc(sizeoffullbuffer);
          network.peek(header, buf, sizeoffullbuffer);

          Serial.print(F("Full buffer: "));
          RF24Signing_random_data_print(buf, sizeoffullbuffer);
          RF24Signing_hash_data((uint8_t *)buf + sizeof(PayloadMetadata), payload.payload_size);

          SentNonce * tempnonce = RF24Signing_sent_noncelist_find_from_ID(nodeID);
          if (tempnonce != 0) {
            Serial.print(F("Nonce used: "));
            Serial.println(tempnonce->nonce);
            RF24Signing_hash_data(&(tempnonce->nonce), sizeof(uint32_t));
          } else {
            Serial.println(F("Nonce not found!"));
            return false; //TODO WARNING: Just keeping the message in the buffer
          }

          uint8_t calculated_hash[32];
          RF24Signing_hash_store(rfsigned.Sha256.resultHmac(), calculated_hash);


          Serial.print(F("Calculated hash: "));
          RF24Signing_hash_print(calculated_hash);
          Serial.print(F("Received hash: "));
          RF24Signing_hash_print(payload.hash);

          free(buf);
          if (RF24Signing_hash_compare(calculated_hash, payload.hash)) {
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
          bool state = mesh.write(&payload, 'N', sizeof(payload), nodeID);
          if (state) {
            RF24Signing_sent_noncelist_add(nodeID, time);
            Serial.println(F("Nonce stored"));
            Serial.println(F("Completed nonce sending"));
            RF24Signing_sent_noncelist_print();
            return false;
          }
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
          RF24Signing_received_noncelist_add(nodeID, payload_nonce.nonce);
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
uint32_t noncelistretrytimer = 0;
void RF24Signing_signed_network_update() {
  mesh.update();

  if (millis() - bufferListMaintenanceTimer > 500) {
    Serial.println(F("Maintenance"));
    if (rfsigned.received_noncelist_first != 0) {
      Serial.println(F("1: Checking for received timeouts"));
      RF24Signing_received_noncelist_remove_timeout();
    }

    if (rfsigned.sent_noncelist_first != 0) {
      Serial.println(F("2: Checking for sent timeouts"));
      RF24Signing_sent_noncelist_remove_timeout();
    }

    /*if (bufferlist_first != 0) {
      Serial.println(F("3: Checking for buffer timeout"));
      RF24Signing_bufferlist_remove_timeout();
      }*/

    if (rfsigned.requested_noncelist_first != 0) {
      Serial.println(F("4: Checking for nonce request timeouts"));
      RF24Signing_requested_noncelist_remove_timeout();
    }

    if (rfsigned.bufferlist_first != 0) {
      Serial.println(F("5: Sending all"));
      RF24Signing_bufferlist_send_all();
    }
    bufferListMaintenanceTimer = millis();
  }

  mesh.update();
  //Serial.println(F("d"));
  if (millis() - noncelistretrytimer > 2000) {
    if (rfsigned.requested_noncelist_first != 0) {
      Serial.println(F("Requesting nonces for all"));
      RF24Signing_requested_noncelist_retry_all();
    }
    noncelistretrytimer = millis();
  }

  mesh.update();
}