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
Signed network maintenance
*/
void SignedNetworkUpdate(){
   ReceivedNonceListRemoveTimeout(firstreceivednonce);
   SentNonceListRemoveTimeout(firstsentnonce);
   BufferListSendAll();
}
/*
Sent nonce linked list functions
*/
sentnonce * SentNonceListFindFromID(sentnonce * start, uint8_t nodeID) {
   sentnonce * current = start;
   while (current->next != NULL) {
      current = current->next;
      if(current->toNodeID == nodeID){
         return current;
      }
   }

   return NULL;
}

bool SentNonceListAdd(sentnonce * start, uint8_t toNodeID, unsigned long int nonce) {
    sentnonce * current = start;
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
   sentnonce * head = NULL;
   head = malloc(sizeof(sentnonce));
   if (head == NULL) {
       return false;
   }

   head->next = NULL;
   return true;
}

void SentNonceListRemove(sentnonce * previous, sentnonce * current){
    previous->next = current->next;
    free(current);
}

void SentNonceListRemoveTimeout(sentnonce * start) {
    sentnonce * current = start;
    sentnonce * previous = NULL;
    while (current->next != NULL) {
        previous = current;
        current = current->next;
        if(millis() - current->nonce > 5000){
         SentNonceListRemove(previous, current);
        }
    }
}

void SentNonceListPrint(sentnonce * start){
   sentnonce * current = start;
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
receivednonce * ReceivedNonceListFindFromID(receivednonce * start, uint8_t nodeID) {
   receivednonce * current = start;
   while (current->next != NULL) {
      current = current->next;
      if(current->fromNodeId == nodeID){
         return current;
      }
   }

   return NULL;
}

bool ReceivedNonceListAdd(receivednonce * start, uint8_t fromNodeId, unsigned long int nonce) {
    receivednonce * current = start;
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
   receivednonce * head = NULL;
   head = malloc(sizeof(receivednonce));
   if (head == NULL) {
       return false;
   }

   head->next = NULL;
   return true;
}

void ReceivedNonceListRemove(receivednonce * previous, receivednonce * current){
    previous->next = current->next;
    free(current);
}

void ReceivedNonceListRemoveTimeout(receivednonce * start) {
    receivednonce * current = start;
    receivednonce * previous = NULL;
    while (current->next != NULL) {
        previous = current;
        current = current->next;
        if(millis() - current->receivedTimestamp > 5000){
            ReceivedNonceListRemove(previous, current);
        }
    }
}

void ReceivedNonceListPrint(receivednonce * start){
   receivednonce * current = start;
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
bufferitem * BufferListFindForID(bufferitem * start, uint8_t nodeID) {
   bufferitem * current = start;
   while (current->next != NULL) {
      current = current->next;
      if(current->bufferItemForNode == nodeID){
         return current;
      }
   }

   return NULL;
}

bool BufferListAdd(bufferitem * start, uint8_t bufferItemForNode, void * payload) {
   bufferitem * current = start;
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
   }
   return true;
}

bool BufferListInitalize(void){
   bufferitem * head = NULL;
   head = malloc(sizeof(bufferitem));
   if (head == NULL) {
       return false;
   }

   head->next = NULL;
   return true;
}

bool BufferListSend(bufferitem * item, receivednonce * nonce){
   size_t buf_size = sizeof(metadata) + item->payload_size; //Calculate the size of the message
   void * buf = malloc(bufsize); //Allocate enough memory for the buffer

   Sha256.initHmac(hmacs[item->toNodeID], 20); //Initialize the hmac
   hashdata(item->payload, item->payload_size); //Hash the data itself
   storeHash(Sha256.result(), item->hash); //Store hash in payload hash

   memmove(buf, item, sizeof(metadata)); //Copy metadata to the start of the buffer
   memmove(buf+sizeof(metadata), item->payload, item->payload_size); //Copy the payload to the end of the buffer
   mesh.write(buf, 'S', buf_size); //Send the message
}

void BufferListSendAll(){

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
    free(current->bufferPayload);
    free(current);
}

void BufferListPrint(bufferitem * start){
   bufferitem * current = start;
   Serial.println(F("___ BUFFER DUMP ___"));
   while (current->next != NULL) {
      current = current->next;
      Serial.print(F("For: "));
      Serial.println(current->bufferItemForNode);
      Serial.print(F("Pointer to next: "));
      Serial.println((int) current->next);
      Serial.print(F("Hash"));
      Serial.println((char)current->bufferPayload->hash[0]);
      Serial.print(F("Payload size"));
      Serial.println(current->bufferPayload->payload_size);
   }
}

/*
Hashing related functions
*/
void hashdata(void * payload, size_t payload_size){
   for (uint8_t i = 0; i < payload_size; i++) { //Read the payload from the
      uint8_t tempdata = 0;
      memmove(tempdata, ((uint8_t)payload) + i, 1); //Increment pointer and copy
      Serial.print(F("Writing..."));                         //the payload byte by byte to the crypto
      Serial.print(i);
      Serial.print(F(" "));
      Sha256.write(tempdata);
   }
}
void storeHash(uint8_t* hash, uint8_t* result_hash) { // Copy the hash.
   memmove(hash[i], result_hash[i], sizeof(&result_hash)/sizeof(uint8_t)); 
}

void printHash(uint8_t* hash) { // Print the hash
  for (int i = 0; i < 32; i++) {
    Serial.print("0123456789abcdef"[hash[i] >> 4]);
    Serial.print("0123456789abcdef"[hash[i] & 0xf]);
  }
  Serial.println();
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
          hashedpayload payload;
          Serial.println(F("Reading data..."));
          network.peek(header, &payload, sizeof(payload));

          Sha256.initHmac(hmacs[header.from_node], 20);

          Serial.println(F("Writing payload to crypto buffer..."));
          hashdata(payload.payload, payload.payload_size);
          Serial.println(F(" "));

          Serial.println(header.from_node);
          unsigned long int tempnonce = GetNonce(header.from_node);
          if (tempnonce != 0) {
            Serial.print(F("Nonce found: "));
            Serial.println(nonce);
            Sha256.write(nonce);
          } else {
            Serial.println(F("Nonce not found!"));
            return false; //WARNING: Just discarding the message
          }
          uint8_t calculated_hash[32];
          storeHash(Sha256.result(), calculated_hash);
          Serial.print(F("Calculated hash: "));
          printHash(calculated_hash);
          Serial.print(F("Received hash: "));
          printHash(payload.hash);
          if (*calculated_hash == *payload_sens.hash) {
            Serial.println(F("EQUAL HASH?!"));
          } else {
            Serial.println(F("Inequal hash!"));
            return false;
          }
          return payload.payload;
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
          byte storing_nonce = StoreNonce(header.from_node, time);
          if (storing_nonce == 1) {
            Serial.print(F("Stored nonce"));

            RF24NetworkHeader header(received_header.from_node, 'N');
            header.nonce_to_node = received_header.from_node;
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
          for (byte i = 0; i < SIZE_OF_ARRAYS; i++) { //Iterate through the slots
            if (nonces_for_node_id[i] == header.from_node && nonces_when_requested[i] != 0) {  //Received and requested from the right node
              Serial.print(F("Recived nonce for message: "));
              Serial.println(i);
              nonces_stored_nonce[i] = payload_nonce.nonce;
              break;
            }
          }
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