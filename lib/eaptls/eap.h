#ifndef OGS_EAP_TLS_H
#define OGS_EAP_TLS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
EAP-TLS Request Packet
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |   Identifier  |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Flags     |      TLS Message Length
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     TLS Message Length        |       TLS Data...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

EAP SUCCESS / FAILURE 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Code      |  Identifier   |            Length             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


enum eap_code{EAP_REQUEST = 1 , EAP_RESPONSE = 2, EAP_SUCCESS = 3, EAP_FAILURE = 4};

typedef struct eap_packet {
	uint8_t code;
	uint8_t	id;
	uint16_t length;
	uint8_t	eap_type;
	uint8_t flag;
	uint32_t tls_message_length;
    char *data;
} eap_packet_t;

void packet2stringHex(uint8_t *eap_raw, eap_packet_t *pkt, size_t tls_len);
void string2packet(char *string, eap_packet_t * pkt);

uint8_t *packet2bytes(eap_packet_t *pkt, size_t tls_len);

void create_request_packet(eap_packet_t *packet, uint8_t flag, char *data,  size_t tls_len, size_t tls_message_length_eap);
void create_failure_packet(eap_packet_t *packet);
void create_success_packet(eap_packet_t *packet);

uint8_t tls_start_flag(void);
uint8_t length_fragment_flag(void);
uint8_t length_flag(void);
uint8_t fragment_flag(void);

int get_NextID(void);



#ifdef __cplusplus
}
#endif

#endif