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

struct sentnonce {
  uint8_t toNodeID;
  unsigned long int nonce;
  sentnonce * next;
};
sentnonce * firstsentnonce;

struct receivednonce {
  uint8_t fromNodeId;
  unsigned long int nonce;
  unsigned long int receivedTimestamp;
  receivednonce * next;
};

receivednonce * firstreceivednonce;

struct payloadmetadata{ //To calculate the size more easily
  uint8_t hash[32];
  uint8_t payload_size;
};

struct bufferitem { //Buffer list item
  uint8_t hash[32];
  uint8_t payload_size;
  uint8_t bufferItemForNode;
  bufferitem * next; 
  void * payload; 
};
bufferitem * firstbufferitem;

struct payload_nonce {
   unsigned long int nonce;
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
void HashData(void * payload, size_t payload_size){
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
void StoreHash(uint8_t * hash, uint8_t * result_hash) { // Copy the hash.
   memmove(result_hash, hash, sizeof(uint8_t)*32); 
}

void PrintHash(uint8_t * hash) { // Print the hash
  for (int i = 0; i < 32; i++) {
    Serial.print("0123456789abcdef"[hash[i] >> 4]);
    Serial.print("0123456789abcdef"[hash[i] & 0xf]);
  }
  Serial.println();
}

/*
Sent nonce linked list functions
*/
sentnonce * SentNonceListFindFromID(uint8_t nodeID) {
   sentnonce * current = firstsentnonce;
   while (current->next != NULL) {
      current = current->next;
      if(current->toNodeID == nodeID){
         return current;
      }
   }

   return NULL;
}

bool SentNonceListAdd(uint8_t toNodeID, unsigned long int nonce) {
    sentnonce * current = firstsentnonce;
    while (current->next != NULL) {
        current = current->next;
    }

    current->next = malloc(sizeof(sentnonce));
    if(current->next == NULL){
      return false;
    }
    current->next->toNodeID = toNodeID;
    current->next->nonce = nonce;
    return true;
}

bool SentNonceListInitalize(void){
   firstsentnonce = malloc(sizeof(sentnonce));
   if (firstsentnonce == NULL) {
       return false;
   }

   firstsentnonce->next = NULL;
   return true;
}

void SentNonceListRemove(sentnonce * previous, sentnonce * current){
    previous->next = current->next;
    free(current);
}

void SentNonceListRemoveTimeout() {
    sentnonce * current = firstsentnonce;
    sentnonce * previous = NULL;
    while (current->next != NULL) {
        previous = current;
        current = current->next;
        if(millis() - current->nonce > 5000){
         SentNonceListRemove(previous, current);
        }
    }
}

void SentNonceListPrint(){
   sentnonce * current = firstsentnonce;
   Serial.println(F("___ SENT NONCE DUMP ___"));
   while (current->next != NULL) {
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
void BufferListPrint(){
   bufferitem * current = firstbufferitem->next;
   Serial.println(F("___ BUFFER DUMP ___"));
   while (current->next != NULL) {
      Serial.print(F("For: "));
      Serial.println(current->bufferItemForNode);
      Serial.print(F("Pointer to next: "));
      Serial.println((uint16_t) current->next);
      Serial.print(F("Hash: "));
      Serial.println((char) current->hash[0]);
      Serial.print(F("Payload size: "));
      Serial.println(current->payload_size);
      current = current->next;
   }
}

receivednonce * ReceivedNonceListFindFromID(uint8_t nodeID) {
   receivednonce * current = firstreceivednonce;
   while (current->next != NULL) {
      current = current->next;
      if(current->fromNodeId == nodeID){
         return current;
      }
   }

   return NULL;
}

bool ReceivedNonceListAdd(uint8_t fromNodeId, unsigned long int nonce) {
    receivednonce * current = firstreceivednonce;
    while (current->next != NULL) {
        current = current->next;
    }

    current->next = malloc(sizeof(receivednonce));
    if(current->next == NULL){
      return false;
    }
    current->next->fromNodeId = fromNodeId;
    current->next->nonce = nonce;
    current->next->receivedTimestamp = millis();
    return true;
}

bool ReceivedNonceListInitalize(void){
   firstreceivednonce = NULL;
   firstreceivednonce = malloc(sizeof(receivednonce));
   if (firstreceivednonce == NULL) {
       return false;
   }

   firstreceivednonce->next = NULL;
   return true;
}

void ReceivedNonceListRemove(receivednonce * previous, receivednonce * current){
    previous->next = current->next;
    free(current);
}

void ReceivedNonceListRemoveTimeout() {
    receivednonce * current = firstreceivednonce;
    receivednonce * previous = NULL;
    while (current->next != NULL) {
        previous = current;
        current = current->next;
        if(millis() - current->receivedTimestamp > 5000){
            ReceivedNonceListRemove(previous, current);
        }
    }
}

void ReceivedNonceListPrint(){
   receivednonce * current = firstreceivednonce;
   Serial.println(F("___ RECIVED NONCE DUMP ___"));
   while (current->next != NULL) {
      current = current->next;
      Serial.print(F("To: "));
      Serial.println(current->fromNodeId);
      Serial.print(F("Nonce: "));
      Serial.println(current->nonce);
      Serial.print(F("Timestamp: "));
      Serial.println(current->receivedTimestamp);
   }
}
void BufferListRemove(bufferitem * previous, bufferitem * current){
    previous->next = current->next;
    free(current->payload);
    free(current);
}

void RequestNonceFromNodeID(uint8_t nodeID){
   payload_nonce payload;
   uint8_t status = mesh.write(&payload,'R', 1, nodeID);
   Serial.print("Status: ");
   Serial.println(status);
}
/* 
Sending buffer related functions
*/
bufferitem * BufferListFindForID(uint8_t nodeID) {
   bufferitem * current = firstbufferitem;
   while (current->next != NULL) {
      current = current->next;
      if(current->bufferItemForNode == nodeID){
         return current;
      }
   }

   return NULL;
}
bool BufferListSend(bufferitem * item, receivednonce * nonce, bufferitem * previousitem){
   Serial.print(" Sending buffer item");
   size_t buf_size = sizeof(payloadmetadata) + item->payload_size; //Calculate the size of the message
   void * buf = malloc(buf_size); //Allocate enough memory for the buffer

   Sha256.initHmac(hmacs[item->bufferItemForNode], 20); //Initialize the hmac
   HashData(item->payload, item->payload_size); //Hash the data itself
   StoreHash(Sha256.result(), item->hash); //Store hash in payload hash

   memmove(buf, item, sizeof(payloadmetadata)); //Copy metadata to the start of the buffer
   memmove(buf+sizeof(payloadmetadata), item->payload, item->payload_size); //Copy the payload to the end of the buffer
   Serial.println("Buffer item prepared.");
   mesh.write(buf, 'S', buf_size); //Send the message
   Serial.println("I guess it's sent");
   BufferListRemove(previousitem, item);
   Serial.println(F("Buffer list"));
   BufferListPrint();

}


bool BufferListAdd(uint8_t bufferItemForNode, void * payload, uint8_t size) {
   Serial.println(F("Added item to buffer list"));
   bufferitem * current = firstbufferitem;
   while (current->next != NULL) {
      current = current->next;
   }

   current->next = malloc(sizeof(receivednonce));
   if(current->next == NULL){
      return false;
   }

   current->next->bufferItemForNode = bufferItemForNode;
   current->next->payload = payload;
   current->next->payload_size = size;

   receivednonce * nonce = ReceivedNonceListFindFromID(bufferItemForNode);
   if(nonce != NULL){
      BufferListSend(current->next, nonce, current);
      return true;
   } else{
      Serial.println(F("Requested nonce"));
      RequestNonceFromNodeID(bufferItemForNode);
      Serial.println(F("Requested"));
      return true;
   }
   return true;
}

bool BufferListInitalize(void){
   firstbufferitem = NULL;
   firstbufferitem = malloc(sizeof(bufferitem));
   if (firstbufferitem == NULL) {
       return false;
   }

   firstbufferitem->next = NULL;
   return true;
}



void BufferListSendAll(){
   bufferitem * current = firstbufferitem;
   while (current->next != NULL) {
      uint32_t nonce = ReceivedNonceListFindFromID(current->bufferItemForNode);
      if(nonce != 0){
         Serial.println(" ..one nonce for node is not 0!");
         BufferListSend(current->next, nonce, current);
      }
      current = current->next;
   }
}

/*  //TODO: Payloads should be dumped at one point
void BufferListRemoveTimeout(bufferitem * start) {
    bufferitem * current = start;
    bufferitem * previous = NULL;
    while (current->next != NULL) {
        previous = current;
        current = current->next;
        if(millis() - current->receivedTimestamp > 5000){
            ReceivedNonceListRemove(previous, current);
        }
    }
}*/

/*
Intercepting signing payloads
*/
bool UnsignedNetworkAvailable(void) {
  if (network.available()) {
    Serial.print(F("NETWORK RECEIVE: "));
    RF24NetworkHeader header;
    network.peek(header);
    Serial.println((char)header.type);
    switch (header.type) { // Is there anything ready for us?
      case 'S': { //"S" like "you sent me something signed"
          Serial.print(F("S Time: "));
          Serial.println(millis());
          payloadmetadata payload;
          Serial.println(F("Reading data..."));
          network.peek(header, &payload, sizeof(payload));
          uint16_t nodeID = mesh.getNodeID(header.from_node);
          Serial.print(F(" message from: "));
          Serial.println(nodeID);
          Sha256.initHmac(hmacs[nodeID], 20);

          Serial.println(F("Writing payload to crypto buffer..."));
          void * buf = malloc(payload.payload_size);
          network.peek(header, buf, sizeof(payloadmetadata)+payload.payload_size);
          HashData(buf, payload.payload_size);
          Serial.println(F("Wrote to crypto buffer"));
          free(buf);

          unsigned long int tempnonce = ReceivedNonceListFindFromID(nodeID);
          if (tempnonce != 0) {
            Serial.print(F("Nonce found: "));
            Serial.println(tempnonce);
            Sha256.write(tempnonce);
          } else {
            Serial.println(F("Nonce not found!"));
            return false; //WARNING: Just discarding the message
          }
          uint8_t calculated_hash[32];
          StoreHash(Sha256.resultHmac(), calculated_hash);
          Serial.print(F("Calculated hash: "));
          PrintHash(calculated_hash);
          Serial.print(F("Received hash: "));
          PrintHash(payload.hash);
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
          unsigned long int time = millis();
          payload.nonce = time;
          Serial.print(F("Sent nonce: "));
          Serial.println(payload.nonce);
          Serial.print(F("To node: "));
          uint16_t nodeID = mesh.getNodeID(received_header.from_node);
          Serial.println(nodeID);
          SentNonceListAdd(nodeID, time);
          mesh.write(&payload, 'N', sizeof(payload), nodeID);
          return false;
        }
      case 'N': { //"N" like "you sent me a nonce"
          struct payload_no {
            unsigned long int nonce;
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
          ReceivedNonceListAdd(nodeID, payload_nonce.nonce);
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
void SignedNetworkUpdate(){
   mesh.update();                          // Check the network regularly
   mesh.DHCP();
   ReceivedNonceListRemoveTimeout();
   SentNonceListRemoveTimeout();
   mesh.update();                          // Check the network regularly
   mesh.DHCP();
   BufferListSendAll();
   mesh.update();                          // Check the network regularly
   mesh.DHCP();
}

void SignedNetworkBegin(){
   SentNonceListInitalize();
   ReceivedNonceListInitalize();
   BufferListInitalize();
}