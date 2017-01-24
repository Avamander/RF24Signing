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

const uint8_t hmacs[][20] PROGMEM = {
  {0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
  {0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b},
};

#include "sha256.h"

extern Sha256Class sha256;
extern RF24Network network;
extern RF24NetworkHeader header;

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
      Sha256.write(tempdata);
   }
}
void StoreHash(uint8_t * hash, uint8_t * result_hash) { // Copy the hash.
   memmove(hash[i], result_hash[i], sizeof(&result_hash)/sizeof(uint8_t)); 
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

bool BufferListAdd(uint8_t bufferItemForNode, void * payload) {
   bufferitem * current = firstbufferitem;
   while (current->next != NULL) {
      current = current->next;
   }

   current->next = malloc(sizeof(receivednonce));
   if(current->next == NULL){
      return false;
   }

   current->next->bufferItemForNode = bufferItemForNode;
   current->next->bufferPayload = payload;

   receivednonce * nonce = ReceivedNonceListFindFromID(bufferItemForNode);
   if(nonce != NULL){
      BufferListSend(current->next, nonce);
      return true;
   } else{
      RequestNonceFromNodeID(bufferItemForNode);
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

bool BufferListSend(bufferitem * item, receivednonce * nonce){
   size_t buf_size = sizeof(metadata) + item->payload_size; //Calculate the size of the message
   void * buf = malloc(bufsize); //Allocate enough memory for the buffer

   Sha256.initHmac(hmacs[item->toNodeID], 20); //Initialize the hmac
   HashData(item->payload, item->payload_size); //Hash the data itself
   StoreHash(Sha256.result(), item->hash); //Store hash in payload hash

   memmove(buf, item, sizeof(metadata)); //Copy metadata to the start of the buffer
   memmove(buf+sizeof(metadata), item->payload, item->payload_size); //Copy the payload to the end of the buffer
   mesh.write(buf, 'S', buf_size); //Send the message
}

void BufferListSendAll(){
   bufferitem * current = firstbufferitem;
   while (current->next != NULL) {
      current = current->next;
      uint32_t nonce = ReceivedNonceListFindFromID(current->bufferItemForNode);
      if(nonce != 0){
         BufferListSend(current, nonce);
      }
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

void BufferListRemove(bufferitem * previous, bufferitem * current){
    previous->next = current->next;
    free(current->payload);
    free(current);
}

void BufferListPrint(){
   bufferitem * current = firstbufferitem;
   Serial.println(F("___ BUFFER DUMP ___"));
   while (current->next != NULL) {
      current = current->next;
      Serial.print(F("For: "));
      Serial.println(current->bufferItemForNode);
      Serial.print(F("Pointer to next: "));
      Serial.println((int) current->next);
      Serial.print(F("Hash"));
      Serial.println((char)current->hash[0]);
      Serial.print(F("Payload size"));
      Serial.println(current->payload_size);
   }
}

/*
Intercepting signing payloads
*/
bool UnsignedNetworkAvailable(void) {
  if (network.available()) {
    Serial.print(F("NETWORK RECEIVE: "));
    network.peek(header);
    Serial.println((char)header.type);
    switch (header.type) { // Is there anything ready for us?
      case 'S': { //"S" like "you sent me something signed"
          Serial.print(F("S Time: "));
          Serial.println(millis());
          payloadmetadata payload;
          Serial.println(F("Reading data..."));
          network.peek(header, &payload, sizeof(payload));

          Sha256.initHmac(hmacs[header.from_node], 20);

          Serial.println(F("Writing payload to crypto buffer..."));
          void * buf = malloc(payload.payload_size);
          network.peek(header, buf, sizeof(payloadmetadata)+payload.payload_size);
          HashData(buf, payload.payload_size);
          free(buf);
          Serial.println(F(" "));

          Serial.println(header.from_node);
          unsigned long int tempnonce = ReceivedNonceListFindFromID(header.from_node);
          if (tempnonce != NULL) {
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
      case 'R': { //"R" like "sent you a nonce"
          Serial.print(F("R Time: "));
          Serial.println(millis());

          struct payload_no {
            unsigned long int nonce;
          };
          payload_no payload_nonce;
          RF24NetworkHeader received_header;

          network.read(received_header, &payload_nonce, sizeof(payload_nonce));
          unsigned long int time = millis();
          byte storing_nonce = SentNonceListAdd(header.from_node, time);
          if (storing_nonce == 1) {
            Serial.print(F("Stored nonce"));
            RF24NetworkHeader header(received_header.from_node, 'N');
            payload_nonce.nonce = time;
            if (network.write(header, &payload_nonce, sizeof(payload_nonce))) {
              Serial.print(F("Sent nonce: "));
            }
            Serial.println(time);
            return false;
          } else if (storing_nonce == 2) {
            Serial.println(F("Unable to store nonce, buffer full"));
          } else if (storing_nonce == 3) {
            Serial.println(F("Node already has valid nonce"));
            return false;
          }
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
          Serial.println(header.from_node);
          ReceivedNonceListAdd(header.from_node, payload_nonce.nonce);
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
   ReceivedNonceListRemoveTimeout();
   SentNonceListRemoveTimeout();
   BufferListSendAll();
}

void SignedNetworkBegin(){
   SentNonceListInitalize();
   ReceivedNonceListInitalize();
   BufferListInitalize();
}