#include "inc/bearssl.h"
#include "eap.h"
#include "chain-rsa.h"
#include "key-rsa.h"
#define SKEY   RSA
#include "trust-anchors.h"
//#include "chain-localhost-root-ec.h"
//#include "key-localhost-root-ec.h"
//#define SKEY   EC
//#include "trust-anchors-ec.h"

#define OGS_SERVER_RANDOM_LEN                32
#define OGS_NAS_MAX_EAP_MESSGE_LEN           1503

typedef struct tls_server_wrapper {
    br_ssl_server_context sc;
    br_x509_minimal_context xc;
    unsigned char obuf[1495];//nas eap message header and eap header. 1503 - (5+2)
    unsigned char ibuf[16709];
    int eap_messages_buffered;
    int next_message;
    int fragment_counter;
    char *buffer[10];
    int messages_len[10];
    int total_messages_len;
    int noRecord;
    uint8_t *random;

} tls_server_wrapper_t;

void init_tls_server(tls_server_wrapper_t *server);



