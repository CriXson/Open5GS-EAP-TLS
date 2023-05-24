#include "tls_server.h"



void init_tls_server(tls_server_wrapper_t *server)
{
    
    //br_ssl_server_init_full_rsa(&(server->sc), CHAIN, CHAIN_LEN, &SKEY);
	br_ssl_server_init_full_ec(&(server->sc), CHAIN, CHAIN_LEN,
			BR_KEYTYPE_EC, &SKEY);
    br_ssl_engine_set_buffers_bidi(&(server->sc.eng), server->ibuf, sizeof server->ibuf, server->obuf, sizeof server->obuf);
    br_ssl_server_reset(&server->sc);
    br_ssl_engine_set_versions(&server->sc.eng, BR_TLS12, BR_TLS12);
    br_ssl_engine_add_flags(&server->sc.eng, BR_OPT_ENFORCE_SERVER_PREFERENCES);
    br_ssl_engine_add_flags(&server->sc.eng, BR_OPT_NO_RENEGOTIATION);
    br_x509_minimal_init(&server->xc, &br_sha256_vtable,
		TAs, TAs_NUM);
	br_ssl_engine_set_default_rsavrfy(&(server->sc.eng));
	br_ssl_engine_set_default_ecdsa(&(server->sc.eng));
	br_x509_minimal_set_rsa(&server->xc, br_ssl_engine_get_rsavrfy(&(server->sc.eng)));
	br_x509_minimal_set_ecdsa(&server->xc,
		br_ssl_engine_get_ec(&(server->sc.eng)),
		br_ssl_engine_get_ecdsa(&(server->sc.eng)));
	br_ssl_engine_set_x509(&(server->sc.eng), &server->xc.vtable);
	
	br_ssl_server_set_trust_anchor_names_alt(&(server->sc), TAs, TAs_NUM);   
    br_ssl_engine_set_prf_sha256(&server->sc.eng, &br_tls12_sha256_prf);
	br_ssl_engine_set_prf_sha384(&server->sc.eng, &br_tls12_sha384_prf);
}