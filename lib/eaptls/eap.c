#include "eap.h"
#include <stdio.h>
#include "../core/ogs-core.h"

const uint16_t EAP_TLS_MIN_LENGTH = 6;
const uint8_t EAP_TYPE_TLS = 13;
int nextID = 100;

void packet2stringHex(uint8_t *eap_raw, eap_packet_t *pkt, size_t tls_len)
{
   
    // int x;
    // size_t len = 0;
    // char *s;
    // char *string;


    // len = snprintf (s, len, "%d%d%d%d", pkt->code, pkt->id, pkt->length, pkt->eap_type); // not clean 
    // size_t t= sizeof *pkt * len +1;
    // string = ogs_calloc(1, len + 1 + tls_len); //sizeof *pkt * len +1
    // x = snprintf (string, len+1, "%d%d%d%d", pkt->code, pkt->id, pkt->length, pkt->eap_type);
    // if (x > (len + 1))
    // {
    //     fprintf (stderr, "%s() error: snprintf returned truncated result.\n", __func__);
    //     return NULL;
    // }

    // if(tls_len != 0){
    //     memcpy(string + len + 1, pkt->data, tls_len);
    // }
    eap_raw[0] = pkt->code;
    eap_raw[1] = pkt->id;
    eap_raw[2] = (pkt->length >> 8) & 0xFF;
    eap_raw[3] = pkt->length & 0xFF; // length needs to be fixed
    if (pkt->code == 3 || pkt->code == 4) {
        return;
    } 
    eap_raw[4] = pkt->eap_type;
    eap_raw[5] = pkt->flag;
    if(pkt->flag == length_flag() || pkt->flag == length_fragment_flag()){ //pkt->flag & (1 << 0)
        eap_raw[6] = pkt->tls_message_length >> 24;
        eap_raw[7] = pkt->tls_message_length >> 16;
        eap_raw[8] = pkt->tls_message_length >> 8;
        eap_raw[9] = pkt->tls_message_length;
        if(tls_len > 0) {
            memcpy(&eap_raw[10], pkt->data, tls_len);
        }
    }else {
        if(tls_len > 0) {
            memcpy(&eap_raw[6], pkt->data, tls_len);
        }
    }
   
}

void string2packet(char *string, eap_packet_t * pkt)
{
   
    pkt->code=(uint8_t) strtok(string, ";"); 
    pkt->id = (uint8_t) strtok(string, ";");
    pkt->length = (uint16_t) strtok(string, ";");
    pkt->eap_type = (uint8_t) strtok(string, ";");
    
    char *ptr = strtok(string, ";");
    if(ptr != NULL){
        uint8_t *data = ogs_calloc(0, sizeof(ptr));
        data = *ptr;
        pkt->data = data;
    }

}

uint8_t *packet2bytes(eap_packet_t *pkt, size_t tls_len)
{
    uint8_t *pkt_raw = ogs_calloc(0, 5+tls_len);

    pkt_raw[0] = pkt->code;
    pkt_raw[1] = pkt->id;
    pkt_raw[2] = pkt->length & 0xff;
    pkt_raw[3] = ((pkt->length) >> 8) & 0xff;
    pkt_raw[4] = pkt->eap_type;

    if(tls_len != 0){
        memcpy(pkt_raw, pkt->data, tls_len);
    }

    return pkt_raw;


}

void create_request_packet(eap_packet_t *packet, uint8_t flag, char *data, size_t tls_len, size_t tls_message_length_eap)
{
    
    //memset(&packet, 0, sizeof(packet) + tls_len); // is it maybe one length to long? because sizeof packet has one byte for data pointer
    packet->code = EAP_REQUEST;
    packet->id = nextID;
    packet->length = EAP_TLS_MIN_LENGTH + tls_len;
    packet->eap_type = EAP_TYPE_TLS;
    packet->flag = flag;
    // ONly non zero if the length flag has been set before;
    if(tls_message_length_eap != 0){
        packet->tls_message_length = tls_message_length_eap;
        packet->length += 4;
    }
    if(tls_len != 0) {
        //memcpy(data, packet->data, tls_len);
        packet->data = data;
    }
    nextID++;
}

void create_failure_packet(eap_packet_t *packet)
{
    packet->code = EAP_FAILURE;
    packet->id = nextID;
    packet->length = 4;
    nextID++;
}

void create_success_packet(eap_packet_t *packet)
{
    packet->code = EAP_SUCCESS;
    packet->id = nextID;
    packet->length = 4;
    nextID++;
}

uint8_t tls_start_flag()
{
    // uint8_t flag = 0;
    // flag |= 0XFF;
    // return flag;
    return 32;
}

uint8_t length_fragment_flag()
{
    return 192;
}

uint8_t length_flag()
{
    return 128;
}

uint8_t fragment_flag()
{
    return 64;
}

int get_NextID()
{
    return nextID;
}