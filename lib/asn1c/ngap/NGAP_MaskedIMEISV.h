/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r16.7.0/38413-g70.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#ifndef	_NGAP_MaskedIMEISV_H_
#define	_NGAP_MaskedIMEISV_H_


#include <asn_application.h>

/* Including external dependencies */
#include <BIT_STRING.h>

#ifdef __cplusplus
extern "C" {
#endif

/* NGAP_MaskedIMEISV */
typedef BIT_STRING_t	 NGAP_MaskedIMEISV_t;

/* Implementation */
extern asn_TYPE_descriptor_t asn_DEF_NGAP_MaskedIMEISV;
asn_struct_free_f NGAP_MaskedIMEISV_free;
asn_struct_print_f NGAP_MaskedIMEISV_print;
asn_constr_check_f NGAP_MaskedIMEISV_constraint;
jer_type_encoder_f NGAP_MaskedIMEISV_encode_jer;
per_type_decoder_f NGAP_MaskedIMEISV_decode_aper;
per_type_encoder_f NGAP_MaskedIMEISV_encode_aper;

#ifdef __cplusplus
}
#endif

#endif	/* _NGAP_MaskedIMEISV_H_ */
#include <asn_internal.h>
