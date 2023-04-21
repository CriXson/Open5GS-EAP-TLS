/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
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

#include "nausf-handler.h"
#include "nas-path.h"

// #include "lib/eaptls/eap_tls.h"

int amf_nausf_auth_handle_authenticate(
    amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    OpenAPI_ue_authentication_ctx_t *UeAuthenticationCtx = NULL;
    OpenAPI_av5g_aka_t *AV5G_AKA = NULL;
    OpenAPI_links_value_schema_t *LinksValueSchemeValue = NULL;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_lnode_t *node = NULL;

    ogs_assert(amf_ue);
    ogs_assert(message);

    UeAuthenticationCtx = message->UeAuthenticationCtx;

    if (!UeAuthenticationCtx)
    {
        ogs_error("[%s] No UeAuthenticationCtx", amf_ue->suci);
        return OGS_ERROR;
    }

    if (UeAuthenticationCtx->auth_type == OpenAPI_auth_type_EAP_AKA_PRIME)
    {
        ogs_error("[%s] Not supported Auth Method [%d]",
                  amf_ue->suci, UeAuthenticationCtx->auth_type);
        return OGS_ERROR;
    }

    if (!UeAuthenticationCtx->_links)
    {
        ogs_error("[%s] No _links", amf_ue->suci);
        return OGS_ERROR;
    }

    OpenAPI_list_for_each(UeAuthenticationCtx->_links, node)
    {
        LinksValueScheme = node->data;
        if (LinksValueScheme)
        {
            if (strcmp(LinksValueScheme->key,
                       OGS_SBI_RESOURCE_NAME_5G_AKA) == 0 ||
                strcmp(LinksValueScheme->key,
                       OGS_SBI_RESOURCE_NAME_EAP_SESSION) == 0)
            {
                LinksValueSchemeValue = LinksValueScheme->value;
                break;
            }
        }
    }

    if (!LinksValueSchemeValue)
    {
        ogs_error("[%s] No _links.auth", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!LinksValueSchemeValue->href)
    {
        ogs_error("[%s] No _links.auth.href", amf_ue->suci);
        return OGS_ERROR;
    }

    if (UeAuthenticationCtx->auth_type == OpenAPI_auth_type_EAP_TLS)
    {
        ogs_info("Selected authenticaton method EAP-TLS");
        // TODO check if eap payload is set and then add it to amf ue. and set link to new eap_session resource

        if (!UeAuthenticationCtx->eap_payload)
        {
            ogs_error("[%s] No eappayload", amf_ue->suci);
            return OGS_ERROR;
        }

        if (amf_ue->eap_session_url)
            ogs_free(amf_ue->eap_session_url);
        amf_ue->eap_session_url =
            ogs_strdup(LinksValueSchemeValue->href);
        ogs_assert(amf_ue->eap_session_url);

        // decode eap_payload and then add (make function tht decodes base64 to byte and then copy these into eap_message array)
        size_t payload_len = sizeof(UeAuthenticationCtx->eap_payload);
        size_t base64Len = ogs_base64_decode_len(UeAuthenticationCtx->eap_payload);
        uint8_t *eap_decoded = ogs_calloc(1, base64Len - 1);
        size_t decode_len = ogs_base64_decode(eap_decoded, UeAuthenticationCtx->eap_payload);
        
        ogs_trace("  EAP_MESSAGE eap_decoded- ");
        ogs_log_hexdump(OGS_LOG_TRACE, eap_decoded, 6);
        amf_ue->eap_message = eap_decoded;
        ogs_trace("  EAP_MESSAGE amf_ue eap meassage- ");
        ogs_log_hexdump(OGS_LOG_TRACE, amf_ue->eap_message, 6);
        amf_ue->eap_message_len = base64Len - 1;
        // amf_ue->eap_message = eap_hex;
    }
    else
    {

        AV5G_AKA = UeAuthenticationCtx->_5g_auth_data;
        if (!AV5G_AKA)
        {
            ogs_error("[%s] No Av5gAka", amf_ue->suci);
            return OGS_ERROR;
        }

        if (!AV5G_AKA->rand)
        {
            ogs_error("[%s] No Av5gAka.rand", amf_ue->suci);
            return OGS_ERROR;
        }

        if (!AV5G_AKA->hxres_star)
        {
            ogs_error("[%s] No Av5gAka.hxresStar", amf_ue->suci);
            return OGS_ERROR;
        }

        if (!AV5G_AKA->autn)
        {
            ogs_error("[%s] No Av5gAka.autn", amf_ue->suci);
            return OGS_ERROR;
        }

        if (amf_ue->confirmation_url_for_5g_aka)
            ogs_free(amf_ue->confirmation_url_for_5g_aka);
        amf_ue->confirmation_url_for_5g_aka =
            ogs_strdup(LinksValueSchemeValue->href);
        ogs_assert(amf_ue->confirmation_url_for_5g_aka);

        ogs_ascii_to_hex(AV5G_AKA->rand, strlen(AV5G_AKA->rand),
                         amf_ue->rand, sizeof(amf_ue->rand));
        ogs_ascii_to_hex(AV5G_AKA->hxres_star, strlen(AV5G_AKA->hxres_star),
                         amf_ue->hxres_star, sizeof(amf_ue->hxres_star));
        ogs_ascii_to_hex(AV5G_AKA->autn, strlen(AV5G_AKA->autn),
                         amf_ue->autn, sizeof(amf_ue->autn));
    }
    if (amf_ue->nas.amf.ksi < (OGS_NAS_KSI_NO_KEY_IS_AVAILABLE - 1))
        amf_ue->nas.amf.ksi++;
    else
        amf_ue->nas.amf.ksi = 0;

    amf_ue->nas.ue.ksi = amf_ue->nas.amf.ksi;

    
    ogs_assert(OGS_OK ==
               nas_5gs_send_authentication_request(amf_ue));

    return OGS_OK;
}

int amf_nausf_auth_handle_authenticate_confirmation(
    amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    uint8_t kseaf[OGS_SHA256_DIGEST_SIZE];

    OpenAPI_confirmation_data_response_t *ConfirmationDataResponse;

    ogs_assert(amf_ue);
    ogs_assert(message);

    ConfirmationDataResponse = message->ConfirmationDataResponse;
    if (!ConfirmationDataResponse)
    {
        ogs_error("[%s] No ConfirmationDataResponse", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!ConfirmationDataResponse->supi)
    {
        ogs_error("[%s] No supi", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!ConfirmationDataResponse->kseaf)
    {
        ogs_error("[%s] No Kseaf", amf_ue->suci);
        return OGS_ERROR;
    }

    amf_ue->auth_result = ConfirmationDataResponse->auth_result;
    ogs_info("AUTH RESULT for suci [%s]: %d", amf_ue->suci, amf_ue->auth_result);
    if (amf_ue->auth_result == OpenAPI_auth_result_AUTHENTICATION_SUCCESS)
    {
        amf_ue_set_supi(amf_ue, ConfirmationDataResponse->supi);
        ogs_ascii_to_hex(ConfirmationDataResponse->kseaf,
                         strlen(ConfirmationDataResponse->kseaf), kseaf, sizeof(kseaf));

        ogs_kdf_kamf(amf_ue->supi, amf_ue->abba, amf_ue->abba_len,
                     kseaf, amf_ue->kamf);

        return OGS_OK;
    }
    else
    {

        ogs_error("[%s] Authentication failed", amf_ue->suci);
        return OGS_ERROR;
    }
}

int amf_nausf_auth_handle_authenticate_eap(amf_ue_t *amf_ue, ogs_sbi_message_t *message)
{
    OpenAPI_eap_session_t *eap_session = NULL;
    OpenAPI_links_value_schema_t *LinksValueSchemeValue = NULL;
    OpenAPI_map_t *LinksValueScheme = NULL;
    OpenAPI_lnode_t *node = NULL;

    ogs_assert(amf_ue);
    ogs_assert(message);

    eap_session = message->EapSession;

    if (!eap_session)
    {
        ogs_error("[%s] No eap_session", amf_ue->suci);
        return OGS_ERROR;
    }

    // todo what happens when success? set kseaf, supi ... but can it be set to success by amf??
    if (eap_session->auth_result == OpenAPI_auth_result_AUTHENTICATION_SUCCESS)
    {
        amf_ue->auth_result = OpenAPI_auth_result_AUTHENTICATION_SUCCESS;
    }

    if (!eap_session->_links)
    {
        ogs_error("[%s] No _links", amf_ue->suci);
        return OGS_ERROR;
    }

    OpenAPI_list_for_each(eap_session->_links, node)
    {
        LinksValueScheme = node->data;
        if (LinksValueScheme)
        {
            if (strcmp(LinksValueScheme->key,
                       OGS_SBI_RESOURCE_NAME_5G_AKA) == 0 ||
                strcmp(LinksValueScheme->key,
                       OGS_SBI_RESOURCE_NAME_EAP_SESSION) == 0)
            {
                LinksValueSchemeValue = LinksValueScheme->value;
                break;
            }
        }
    }

    if (!LinksValueSchemeValue)
    {
        ogs_error("[%s] No _links.auth", amf_ue->suci);
        return OGS_ERROR;
    }

    if (!LinksValueSchemeValue->href)
    {
        ogs_error("[%s] No _links.auth.href", amf_ue->suci);
        return OGS_ERROR;
    }

    size_t payload_len = sizeof(eap_session->eap_payload);
    size_t base64Len = ogs_base64_decode_len(eap_session->eap_payload);
    uint8_t *eap_decoded = ogs_calloc(1, base64Len - 1);//why -2 
    size_t decode_len = ogs_base64_decode(eap_decoded, eap_session->eap_payload);

    ogs_trace("  EAP_MESSAGE eap_decoded- ");
    ogs_log_hexdump(OGS_LOG_TRACE, eap_decoded, base64Len - 1);
    amf_ue->eap_message = eap_decoded;
    ogs_trace("  EAP_MESSAGE amf_ue eap meassage- ");
    ogs_log_hexdump(OGS_LOG_TRACE, amf_ue->eap_message, base64Len - 1);
    amf_ue->eap_message_len = decode_len;

    ogs_trace("  EAP_MESSAGE - ");
    ogs_log_hexdump(OGS_LOG_TRACE, amf_ue->eap_message, 5);
    ogs_assert(OGS_OK ==
               nas_5gs_send_authentication_request(amf_ue));

    return OGS_OK;
}