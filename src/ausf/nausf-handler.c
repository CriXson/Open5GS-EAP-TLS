/*
 * Copyright (C) 2019,2020 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "sbi-path.h"
#include "nnrf-handler.h"
#include "nausf-handler.h"

bool ausf_nausf_auth_handle_authenticate(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_authentication_info_t *AuthenticationInfo = NULL;
    char *serving_network_name = NULL;

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    AuthenticationInfo = recvmsg->AuthenticationInfo;
    if (!AuthenticationInfo) {
        ogs_error("[%s] No AuthenticationInfo", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "[%s] No AuthenticationInfo", ausf_ue->suci));
        return false;
    }

    serving_network_name = AuthenticationInfo->serving_network_name;
    ogs_info("serving network name: %s", serving_network_name);
    if (!serving_network_name) {
        ogs_error("[%s] No servingNetworkName", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "[%s] No servingNetworkName", ausf_ue->suci));
        return false;
    }

    if (ausf_ue->serving_network_name)
        ogs_free(ausf_ue->serving_network_name);
    ausf_ue->serving_network_name = ogs_strdup(serving_network_name);
    ogs_assert(ausf_ue->serving_network_name);

    ogs_assert(true ==
        ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_get,
            ausf_ue, stream, AuthenticationInfo->resynchronization_info));

    return true;
}

bool ausf_nausf_auth_handle_authenticate_confirmation(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    OpenAPI_confirmation_data_t *ConfirmationData = NULL;
    char *res_star_string = NULL;
    uint8_t res_star[OGS_KEYSTRLEN(OGS_MAX_RES_LEN)];

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    ConfirmationData = recvmsg->ConfirmationData;
    if (!ConfirmationData) {
        ogs_error("[%s] No ConfirmationData", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "[%s] No ConfirmationData", ausf_ue->suci));
        return false;
    }

    res_star_string = ConfirmationData->res_star;
    if (!res_star_string) {
        ogs_error("[%s] No ConfirmationData.resStar", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "[%s] No ConfirmationData.resStar", ausf_ue->suci));
        return false;
    }

    ogs_ascii_to_hex(res_star_string, strlen(res_star_string),
            res_star, sizeof(res_star));

    if (memcmp(res_star, ausf_ue->xres_star, OGS_MAX_RES_LEN) != 0) {
        ogs_log_hexdump(OGS_LOG_WARN, res_star, OGS_MAX_RES_LEN);
        ogs_log_hexdump(OGS_LOG_WARN, ausf_ue->xres_star, OGS_MAX_RES_LEN);

        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_FAILURE;
    } else {
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
    }

    ogs_assert(true ==
        ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_result_confirmation_inform,
            ausf_ue, stream, NULL));

    return true;
}

bool ausf_nausf_auth_handle_authentication_eap_session(ausf_ue_t *ausf_ue,
        ogs_sbi_stream_t *stream, ogs_sbi_message_t *recvmsg)
{
    ogs_sbi_server_t *server = NULL;

    ogs_sbi_message_t sendmsg;
    ogs_sbi_header_t header;
    ogs_sbi_response_t *response = NULL;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_links_value_schema_t LinksValueSchemeValue;
    OpenAPI_eap_session_t *eap_session = NULL;
    

    ogs_assert(ausf_ue);
    ogs_assert(stream);
    ogs_assert(recvmsg);

    ogs_assert(stream);
    server = ogs_sbi_server_from_stream(stream);
    ogs_assert(server);

    eap_session = recvmsg->EapSession;
    if (!eap_session) {
        ogs_error("[%s] No eap_session", ausf_ue->suci);
        ogs_assert(true ==
            ogs_sbi_server_send_error(stream, OGS_SBI_HTTP_STATUS_BAD_REQUEST,
                recvmsg, "[%s] No eap_session", ausf_ue->suci));
        return false;
    }

    ogs_info("auth result: [%d]",eap_session->auth_result);
    ogs_info("auth result: [%s]",eap_session->eap_payload);
    int len = ogs_base64_decode_len(eap_session->eap_payload);
    uint8_t eap_packet_raw[len];
    ogs_base64_decode(eap_packet_raw, eap_session->eap_payload);
    ogs_info("eap decoded: [%s]",eap_packet_raw);
    eap_packet_t payload;
    memset(&payload, 0, sizeof(payload));
    payload.code = eap_packet_raw[0];
    payload.id = eap_packet_raw[1];
    payload.length = ((uint16_t)eap_packet_raw[2] << 8) | eap_packet_raw[3];
    payload.eap_type = eap_packet_raw[4];
    payload.flag = eap_packet_raw[5];
    

    int eap_length = 6; 
    if(payload.length > 6) {
        //check if tls length flag is set
        if(payload.flag == length_fragment_flag()){ 
            eap_length += 4;
            payload.data = &eap_packet_raw[10];
        }else {
            payload.data = &eap_packet_raw[6];
        }
    }
    uint16_t tls_rec_len = (payload.length - eap_length); 
    if(payload.code == EAP_FAILURE){
        //TODO 
        ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "Received EAP Code is EAP FAILURE", ausf_ue->suci));
        return false;
    }else if(payload.code != EAP_RESPONSE) {
        //todo
        ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "Unexpected EAP Code", ausf_ue->suci));
        return false;
    }
    //TODO check if correct ID or if ID is too old(replay attack)
    uint8_t currentID = get_NextID()
    if(currentID !0) {
        currentID--;
    }
    ogs_info("Expected EAP ID: %d Received EAP ID: %d", currentID, payload.id);
    if(currentID != payload.id){
        ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "Wrong EAP ID", ausf_ue->suci));
        return false;
        // todo  rfc3748 says silently ignore
    }

    eap_packet_t payload_ret;
    int result = write_and_read_tls_server(&payload, &payload_ret, ausf_ue, tls_rec_len, stream);
    if(result < 1){
        int error = br_ssl_engine_last_error(&ausf_ue->tls_server->sc.eng);
        ogs_info("last error from ssl engine %d", error);
        ogs_assert(true ==
                ogs_sbi_server_send_error(stream,
                    OGS_SBI_HTTP_STATUS_INTERNAL_SERVER_ERROR,
                    recvmsg, "TLS FAIL", ausf_ue->suci));
        return false;
    }
    ogs_assert(&payload_ret);
    int eap_message_len = payload_ret.length; // wrong if we have tls flag length set and therefore tls message length 32 octet
    
    int payload_len = 0;
    if(payload_ret.data) {
        payload_len = eap_message_len - 6;
        if(payload_ret.flag == length_flag() || payload_ret.flag == length_fragment_flag()){
            payload_len -= 4;
        }
    }
    
    uint8_t eap_bytes[eap_message_len]; 
    memset(eap_bytes, 0, eap_message_len);
    packet2stringHex(eap_bytes ,&payload_ret, payload_len);
    ogs_info("EAP paket string hex: %s", eap_bytes);
    size_t base64Len = ogs_base64_encode_len(eap_message_len);
    char *eap_base64 = ogs_calloc(1, base64Len); 
    ogs_base64_encode(eap_base64,  eap_bytes, eap_message_len); 
    ogs_info("String Base64: [%s]", eap_base64);
    ogs_info("len string base64: [%lu]", strlen(eap_base64));

    memset(&LinksValueSchemeValue, 0, sizeof(LinksValueSchemeValue));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;
    header.resource.component[2] =(char *)OGS_SBI_RESOURCE_NAME_EAP_SESSION;
    
    LinksValueSchemeValue.href = ogs_sbi_server_uri(server, &header);
    LinksValueScheme = OpenAPI_map_create(
            (char *)OGS_SBI_RESOURCE_NAME_EAP_SESSION,
            &LinksValueSchemeValue);

    OpenAPI_eap_session_t eap_session_ret;
    memset(&eap_session_ret, 0, sizeof(OpenAPI_eap_session_t));
    eap_session_ret.auth_result = ausf_ue->auth_result;
    eap_session_ret.eap_payload = eap_base64;
    eap_session_ret._links = OpenAPI_list_create();
    OpenAPI_list_add(eap_session_ret._links, LinksValueScheme);

    memset(&sendmsg, 0, sizeof(sendmsg));

    memset(&header, 0, sizeof(header));
    header.service.name = (char *)OGS_SBI_SERVICE_NAME_NAUSF_AUTH;
    header.api.version = (char *)OGS_SBI_API_V1;
    header.resource.component[0] =
            (char *)OGS_SBI_RESOURCE_NAME_UE_AUTHENTICATIONS;
    header.resource.component[1] = ausf_ue->ctx_id;

    sendmsg.http.location = ogs_sbi_server_uri(server, &header);
    sendmsg.http.content_type = (char *)OGS_SBI_CONTENT_3GPPHAL_TYPE;

    sendmsg.EapSession = &eap_session_ret;

    response = ogs_sbi_build_response(&sendmsg,
        OGS_SBI_HTTP_STATUS_CREATED);
    ogs_assert(response);
    ogs_assert(true == ogs_sbi_server_send_response(stream, response));
    //maybe correct not 100% sure ^^
    //ogs_sbi_server_remove(server); this throws an segmentation fault so i think its wrong
    //----------------
    
    OpenAPI_list_free(eap_session_ret._links);
    OpenAPI_map_free(LinksValueScheme);

    ogs_free(LinksValueSchemeValue.href);
    ogs_free(sendmsg.http.location);
    ogs_free(sendmsg.EapSession->eap_payload);

    return true;
}


/*
 * Decode an hexadecimal string. Returned value is the number of decoded
 * bytes.
 * 
 * from BearSSl
 */
static size_t
hextobin(unsigned char *dst, const char *src)
{
	size_t num;
	unsigned acc;
	int z;

	num = 0;
	z = 0;
	acc = 0;
	while (*src != 0) {
		int c = *src ++;
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else if (c >= 'A' && c <= 'F') {
			c -= ('A' - 10);
		} else if (c >= 'a' && c <= 'f') {
			c -= ('a' - 10);
		} else {
			continue;
		}
		if (z) {
			*dst ++ = (acc << 4) + c;
			num ++;
		} else {
			acc = c;
		}
		z = !z;
	}
	return num;
}

int write_and_read_tls_server(eap_packet_t *payload, eap_packet_t *payload_ret, ausf_ue_t *ausf_ue, int tls_rec_len, ogs_sbi_stream_t *stream)
{
    
    unsigned state;
    int bytes_written = 0;
    char *tls_new_record= NULL;
    int tls_new_record_len;
   
    br_ssl_engine_context *cc = &(ausf_ue->tls_server->sc.eng);
    if(ausf_ue->tls_server->eap_messages_buffered == 0){
        for(;;)
        {
            if (bytes_written >= tls_rec_len) {
                break;
            }
            state = br_ssl_engine_current_state(cc);
            if (state & BR_SSL_CLOSED) {
                int x = br_ssl_engine_last_error(cc);
                ogs_info("Engine closed last error code is : %d", x);
                return -1;
            }
            if (payload->data){
                int x = state & BR_SSL_RECVREC;
                if (state == BR_SSL_RECVREC) {
                    unsigned char *buf;
                    size_t len;
                    //todo tls record header einlesen(5 bytes) und dann die restliche nachricht also die tls handshake message
                    buf = br_ssl_engine_recvrec_buf(cc, &len);
                    if (len != 0 ){
                        char *p = payload->data+bytes_written;
                        ogs_trace("  BYTES WRITTEN TO BEARSSL ENGINE- ");
                        ogs_log_hexdump(OGS_LOG_TRACE, p, len);
                        ogs_info("first byte written from payload data: %x", *p);
                        ogs_info("last byte written from payload data: %x", *(p+(len-1)));
                        int write_len =0;
                        // if(len > (tls_rec_len-bytes_written)){
                        //     write_len = tls_rec_len-bytes_written;
                        //     memcpy(buf, p, len);
                        //     bytes_written += write_len;
                        // }else {
                        //     memcpy(buf, p, len);
                        //     write_len = len;
                        //     bytes_written += len;
                        // }
                        memcpy(buf, p, len);
                        bytes_written += len;
                        br_ssl_engine_recvrec_ack(cc, len);
                    }
                }else {
                    break;
                    
                }
            }else {
                break;
            }
            // if(bytes_written >= tls_rec_len){
            //     break;https://git.inf.h-brs.de/jroett2s/test_n3iwf_v2.git

            // }
        }
        

        //get new tls record
        int i=0;
        ausf_ue->tls_server->noRecord = 1;
        for(;i<10;i++){
            state = br_ssl_engine_current_state(cc);
            size_t x;
            br_ssl_engine_sendrec_buf(cc, &x);
            if (state & BR_SSL_CLOSED) {
                int x = br_ssl_engine_last_error(cc);
                ogs_info("Engine closed last error code is : %d", x);
                return -1; // send failure
            }
            // BR_SSL_SENDREC. check if there is record data to send. check if flag is set. flag can be set even if state is 4
            if (state & BR_SSL_SENDREC) {
                unsigned char *buf;
                size_t len;

                buf = br_ssl_engine_sendrec_buf(cc, &len);
                if (len == 0){
                    break;
                }
                char * tls_new_record = ogs_malloc(len);
                tls_new_record_len = len;
                ausf_ue->tls_server->buffer[ausf_ue->tls_server->fragment_counter] = tls_new_record;
                ausf_ue->tls_server->messages_len[ausf_ue->tls_server->fragment_counter] = len;
                ausf_ue->tls_server->total_messages_len += len;
                
                memcpy(tls_new_record, buf, len);
                br_ssl_engine_sendrec_ack(cc, len);
                if( ausf_ue->tls_server->fragment_counter==1){
                    ausf_ue->tls_server->eap_messages_buffered = 1;
                }
                ausf_ue->tls_server->fragment_counter++;
                ausf_ue->tls_server->noRecord = 0;
                if(!ausf_ue->tls_server->random) {
                    //ogs hex to sth?
                    ausf_ue->tls_server->random = ogs_malloc(OGS_SERVER_RANDOM_LEN);
                    memcpy(ausf_ue->tls_server->random, &tls_new_record[11], OGS_SERVER_RANDOM_LEN);
                    ogs_trace("  random in tls record- ");
                    ogs_log_hexdump(OGS_LOG_TRACE, &tls_new_record[11], OGS_SERVER_RANDOM_LEN);
                    ogs_trace("  random in ausf_ue ");
                    ogs_log_hexdump(OGS_LOG_TRACE, ausf_ue->tls_server->random, 32);
                }
            } else {
                break;
            }
            // if (state & BR_SSL_RECVREC || state & BR_SSL_SENDAPP || state & BR_SSL_RECVAPP) {
            //     break;
            // }
        }
    }else {
        //if buffered messages still there we expect an ACK coming as a EAP-RESPONSE messages with no data
        if(payload->data) {
            ogs_error("Expected an ACK");
            return -1;
        }
    }
    memset(payload_ret, 0, sizeof(payload_ret));
    uint8_t flags;
    //this if is outside of the else above because otherwise the first fragment would not be sent. As the fragments 
    //come from the for in clause above
    if (ausf_ue->tls_server->eap_messages_buffered == 1){
        if ( ausf_ue->tls_server->total_messages_len < (OGS_NAS_MAX_EAP_MESSGE_LEN-8)) {//
            char *data = ogs_malloc(ausf_ue->tls_server->total_messages_len);
            int i= 0;
            for(;i < ausf_ue->tls_server->fragment_counter;i++){
                char *p = data;
                if(i!=0){
                    p = p+ausf_ue->tls_server->messages_len[i-1];
                }
                memcpy(p, ausf_ue->tls_server->buffer[i], ausf_ue->tls_server->messages_len[i]);
                //ogs_free(&ausf_ue->tls_server->buffer[i]);
            }
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_ONGOING;
            create_request_packet(payload_ret, 0, data, ausf_ue->tls_server->total_messages_len, 0);
            ausf_ue->tls_server->eap_messages_buffered = 0;
            ausf_ue->tls_server->next_message =0;
            ausf_ue->tls_server->fragment_counter = 0;
            ausf_ue->tls_server->total_messages_len = 0;
            ogs_trace("  MESSAGE sent int request packet - ");
            ogs_log_hexdump(OGS_LOG_TRACE, data, ausf_ue->tls_server->total_messages_len);
            return 1;
        }
        if(ausf_ue->tls_server->next_message  == 0){
            // first fragment. Length and Fragment Flag set
            flags = length_fragment_flag();
            create_request_packet(payload_ret, flags, ausf_ue->tls_server->buffer[ausf_ue->tls_server->next_message], 
            ausf_ue->tls_server->messages_len[ausf_ue->tls_server->next_message], ausf_ue->tls_server->total_messages_len);
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_ONGOING;
            ogs_trace("  MESSAGE sent int request packet - ");
            ogs_log_hexdump(OGS_LOG_TRACE, ausf_ue->tls_server->buffer[ausf_ue->tls_server->next_message], 
            ausf_ue->tls_server->messages_len[ausf_ue->tls_server->next_message]);
        } else if ( ausf_ue->tls_server->next_message == ausf_ue->tls_server->fragment_counter-1){ 
            // fragment counter - 1 because next_message starts at 0 and fragment_counter at 1
            //Last fragment. no flags set
            flags = 0;
            create_request_packet(payload_ret, flags, ausf_ue->tls_server->buffer[ausf_ue->tls_server->next_message], 
            ausf_ue->tls_server->messages_len[ausf_ue->tls_server->next_message], 0);
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_ONGOING;
            ogs_trace("  MESSAGE sent int request packet - ");
            ogs_log_hexdump(OGS_LOG_TRACE, ausf_ue->tls_server->buffer[ausf_ue->tls_server->next_message], 
            ausf_ue->tls_server->messages_len[ausf_ue->tls_server->next_message]);
        }else {
            // all fragments between first and last. Fragment flag set
            flags = fragment_flag();
            create_request_packet(payload_ret, flags, ausf_ue->tls_server->buffer[ausf_ue->tls_server->next_message], 
            ausf_ue->tls_server->messages_len[ausf_ue->tls_server->next_message], 0);
            ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_ONGOING;
            ogs_trace("  MESSAGE sent int request packet - ");
            ogs_log_hexdump(OGS_LOG_TRACE, ausf_ue->tls_server->buffer[ausf_ue->tls_server->next_message], 
            ausf_ue->tls_server->messages_len[ausf_ue->tls_server->next_message]);
        }
        //index for next fragment increment
        ausf_ue->tls_server->next_message++;
        //If last fragment was just put into a packet then reset the buffer settings
        if(ausf_ue->tls_server->next_message == ausf_ue->tls_server->fragment_counter){
            ausf_ue->tls_server->eap_messages_buffered = 0;
            ausf_ue->tls_server->next_message =0;
            ausf_ue->tls_server->fragment_counter = 0;
            ausf_ue->tls_server->total_messages_len = 0;
            int i= 0;
            for(;i < ausf_ue->tls_server->fragment_counter;i++){
                ogs_free(&ausf_ue->tls_server->buffer[i]);
            }
        }
        return 1;
    } 
    //Does the bit operation work correctly?
    if(state & BR_SSL_SENDAPP || state & BR_SSL_RECVAPP) {
        //handshake done
        //calc KAUSF
        
        br_ssl_session_parameters pp;
        memset(&pp, 0, sizeof pp);
        br_ssl_engine_get_session_parameters(cc, &pp);
        //TLS-PRF-128(master_secret, "client EAP encryption", client.random || server.random)
        // unsigned char emsk[128];
        // //sha256 if sha256 has been used before 
        // unsigned char *ssecret = ogs_calloc(0, 48);
        // memcpy(ssecret, pp.master_secret, 48);
        //const uint8_t *seedData = ogs_calloc(0, 32);
        //memcpy(seedData, ausf_ue->tls_server->random, 32);
        // const br_tls_prf_seed_chunk seed = {ausf_ue->tls_server->random, 32};
        const char *label = "clientEAPencryption";
        unsigned char secret[100], seed[100], ref[500], out[500];
        size_t secret_len, seed_len, ref_len;
        br_tls_prf_seed_chunk chunks[2];
        secret_len = hextobin(secret, pp.master_secret);
        seed_len = hextobin(seed, ausf_ue->tls_server->random);
        //ogs_free(ssecret);
        //ref_len = hextobin(ref, sref);
        chunks[0].data = seed;
	    chunks[0].len = seed_len;
        // TS33.501 Annex B.2.1
        br_tls12_sha256_prf(out, 200, pp.master_secret, 48, label, seed_len, chunks ); 
        ogs_trace("  EMSK ------- - ");
        ogs_log_hexdump(OGS_LOG_TRACE, out,128);
        memcpy(ausf_ue->kausf, out, 64);
        //and now I coould calc kseaf here
        ogs_kdf_kseaf(ausf_ue->serving_network_name, ausf_ue->kausf, ausf_ue->kseaf);
        //
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
        create_success_packet(payload_ret);
        ogs_assert(true ==
        ausf_sbi_discover_and_send(
            OGS_SBI_SERVICE_TYPE_NUDM_UEAU, NULL,
            ausf_nudm_ueau_build_result_confirmation_inform,
            ausf_ue, stream, NULL));
        int sucess = br_ssl_server_reset(&ausf_ue->tls_server->sc);
        ogs_info("tls server reset success: %d", sucess);
        return 1;
    }
    if(ausf_ue->tls_server->noRecord) {
        //send eap ack? - request packet without data
        
        ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_ONGOING;
        create_request_packet(payload_ret, 0, NULL, 0, 0);
        ogs_trace("EAP ACK SENT");
        return 1;
    }
    //TLS handshake message fits into one record 
    ausf_ue->tls_server->fragment_counter = 0; 
    ausf_ue->tls_server->total_messages_len = 0;
    ausf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_ONGOING;
    create_request_packet(payload_ret, 0, ausf_ue->tls_server->buffer[0], ausf_ue->tls_server->messages_len[0], 0);
    ogs_trace("  MESSAGE sent int request packet - ");
    ogs_log_hexdump(OGS_LOG_TRACE, ausf_ue->tls_server->buffer[0], 
    ausf_ue->tls_server->messages_len[0]);
    return 1;
}
