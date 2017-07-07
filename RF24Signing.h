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

#include "sha256.h"
#include <Arduino.h>
#include <avr/pgmspace.h>
#include "RF24.h"
#include "RF24Mesh.h"
#include "RF24Network.h"
#include "sha256.h"

extern class RF24Network network;
extern class RF24Mesh mesh;

#ifndef __RF24Signing_H__
#define __RF24Signing_H__


#ifdef __cplusplus
extern "C" {
#endif

typedef struct SentNonce {
  uint8_t toNodeID = 255;
  uint32_t nonce = 0;
  SentNonce * next = 0;
};

typedef struct ReceivedNonce {
  uint8_t fromNodeId = 255;
  uint32_t nonce = 0;
  uint32_t receivedTimestamp = 0;
  ReceivedNonce * next = 0;
};

typedef struct PayloadMetadata { //To calculate the size more easily
  uint8_t hash[32] = {0};
  uint8_t payload_size = 0;
};

typedef struct BufferListItem { //Buffer list item
  uint8_t hash[32] = {0};
  uint8_t payload_size = 0;
  uint8_t BufferListItemForNode = 0;
  BufferListItem * next = 0;
  BufferListItem * payload = 0;
};

typedef struct payload_nonce {
  uint32_t nonce = 0;
};

typedef struct RequestedNonce {
  uint8_t fromNodeId = 255;
  uint32_t time = 0;
  uint32_t lastrequest = 0;
  RequestedNonce * next = 0;
};

typedef struct {

Sha256Class Sha256;

//#import "hmacs.c"

SentNonce * sent_noncelist_first = 0;

ReceivedNonce * received_noncelist_first = 0;

RequestedNonce * requested_noncelist_first = 0;

BufferListItem * bufferlist_first = 0;

uint32_t bufferListMaintenanceTimer = 0;

uint32_t noncelistretrytimer = 0;

uint8_t current_node_ID;

} RF24Signing_;

void RF24Signing_signed_network_begin(uint8_t passed_nodeID);

void RF24Signing_hash_data(void * payload, size_t payload_size);

void RF24Signing_hash_print(uint8_t * hash);

void RF24Signing_hash_store(void * hash, void * result_hash);

bool RF24Signing_hash_compare(void * hash1, void * hash2);

void RF24Signing_requested_noncelist_print(void);

void RF24Signing_sent_noncelist_print(void);

void RF24Signing_bufferlist_print(void);

void RF24Signing_received_noncelist_print(void);

void RF24Signing_random_data_print(void * data, size_t size);

bool RF24Signing_sent_noncelist_initialize(void);

bool RF24Signing_received_noncelist_initialize(void);

bool RF24Signing_bufferlist_initialize(void);

bool RF24Signing_requested_noncelist_initialize(void);

void RF24Signing_request_nonce_from_node_id(uint8_t nodeID);

bool RF24Signing_requested_noncelist_add(uint8_t passed_nodeID);

bool RF24Signing_requested_noncelist_delete(RequestedNonce * previous, RequestedNonce * current);

bool RF24Signing_requested_noncelist_received(uint8_t passed_nodeID);

RequestedNonce * RF24Signing_requested_noncelist_find_for_nodeID(uint8_t passed_nodeID);

bool RF24Signing_requested_noncelist_retry_all(void);

bool RF24Signing_requested_noncelist_remove_timeout(void);

SentNonce * RF24Signing_sent_noncelist_find_from_ID(uint8_t nodeID);

bool RF24Signing_sent_noncelist_add(uint8_t toNodeID, uint32_t nonce);

void RF24Signing_sent_noncelist_remove(SentNonce * previous, SentNonce * current);

void RF24Signing_sent_noncelist_remove_timeout(void);

ReceivedNonce * RF24Signing_received_noncelist_find_from_ID(uint8_t nodeID);

bool RF24Signing_received_noncelist_add(uint8_t passed_fromNodeId, uint32_t passed_nonce);

void RF24Signing_received_noncelist_remove(ReceivedNonce * previous, ReceivedNonce * current);

void RF24Signing_received_noncelist_remove_timeout(void);

void RF24Signing_bufferlist_remove(BufferListItem * previous, BufferListItem * current);

BufferListItem * RF24Signing_bufferlist_find_for_id(uint8_t nodeID);

void RF24Signing_read_hmac_from_progmem(uint8_t nodeID, BufferListItem * hmac_pointer);

bool RF24Signing_bufferlist_send(BufferListItem * item, ReceivedNonce * nonce, BufferListItem * previousitem);

bool RF24Signing_bufferlist_add(uint8_t for_node, void * payload, uint8_t size);

void RF24Signing_bufferlist_send_all(void);

bool RF24Signing_unsigned_network_available(void);

void RF24Signing_signed_network_update(void);

#ifdef __cplusplus
}
#endif 

//#ifdef __cplusplus
//#include "cpp_wrapper.h" 
//#endif

#endif // __RF24_H__