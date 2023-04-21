/*
 * Generated by asn1c-0.9.29 (http://lionet.info/asn1c)
 * From ASN.1 module "NGAP-IEs"
 * 	found in "../support/ngap-r16.7.0/38413-g70.asn"
 * 	`asn1c -pdu=all -fcompound-names -findirect-choice -fno-include-deps -no-gen-BER -no-gen-XER -no-gen-OER -no-gen-UPER`
 */

#include "NGAP_Paging-eDRX-Cycle.h"

/*
 * This type is implemented using NativeEnumerated,
 * so here we adjust the DEF accordingly.
 */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
asn_per_constraints_t asn_PER_type_NGAP_Paging_eDRX_Cycle_constr_1 CC_NOTUSED = {
	{ APC_CONSTRAINED | APC_EXTENSIBLE,  4,  4,  0,  13 }	/* (0..13,...) */,
	{ APC_UNCONSTRAINED,	-1, -1,  0,  0 },
	0, 0	/* No PER value map */
};
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
static const asn_INTEGER_enum_map_t asn_MAP_NGAP_Paging_eDRX_Cycle_value2enum_1[] = {
	{ 0,	6,	"hfhalf" },
	{ 1,	3,	"hf1" },
	{ 2,	3,	"hf2" },
	{ 3,	3,	"hf4" },
	{ 4,	3,	"hf6" },
	{ 5,	3,	"hf8" },
	{ 6,	4,	"hf10" },
	{ 7,	4,	"hf12" },
	{ 8,	4,	"hf14" },
	{ 9,	4,	"hf16" },
	{ 10,	4,	"hf32" },
	{ 11,	4,	"hf64" },
	{ 12,	5,	"hf128" },
	{ 13,	5,	"hf256" }
	/* This list is extensible */
};
static const unsigned int asn_MAP_NGAP_Paging_eDRX_Cycle_enum2value_1[] = {
	1,	/* hf1(1) */
	6,	/* hf10(6) */
	7,	/* hf12(7) */
	12,	/* hf128(12) */
	8,	/* hf14(8) */
	9,	/* hf16(9) */
	2,	/* hf2(2) */
	13,	/* hf256(13) */
	10,	/* hf32(10) */
	3,	/* hf4(3) */
	4,	/* hf6(4) */
	11,	/* hf64(11) */
	5,	/* hf8(5) */
	0	/* hfhalf(0) */
	/* This list is extensible */
};
const asn_INTEGER_specifics_t asn_SPC_NGAP_Paging_eDRX_Cycle_specs_1 = {
	asn_MAP_NGAP_Paging_eDRX_Cycle_value2enum_1,	/* "tag" => N; sorted by tag */
	asn_MAP_NGAP_Paging_eDRX_Cycle_enum2value_1,	/* N => "tag"; sorted by N */
	14,	/* Number of elements in the maps */
	15,	/* Extensions before this member */
	1,	/* Strict enumeration */
	0,	/* Native long size */
	0
};
static const ber_tlv_tag_t asn_DEF_NGAP_Paging_eDRX_Cycle_tags_1[] = {
	(ASN_TAG_CLASS_UNIVERSAL | (10 << 2))
};
asn_TYPE_descriptor_t asn_DEF_NGAP_Paging_eDRX_Cycle = {
	"Paging-eDRX-Cycle",
	"Paging-eDRX-Cycle",
	&asn_OP_NativeEnumerated,
	asn_DEF_NGAP_Paging_eDRX_Cycle_tags_1,
	sizeof(asn_DEF_NGAP_Paging_eDRX_Cycle_tags_1)
		/sizeof(asn_DEF_NGAP_Paging_eDRX_Cycle_tags_1[0]), /* 1 */
	asn_DEF_NGAP_Paging_eDRX_Cycle_tags_1,	/* Same as above */
	sizeof(asn_DEF_NGAP_Paging_eDRX_Cycle_tags_1)
		/sizeof(asn_DEF_NGAP_Paging_eDRX_Cycle_tags_1[0]), /* 1 */
	{
#if !defined(ASN_DISABLE_OER_SUPPORT)
		0,
#endif  /* !defined(ASN_DISABLE_OER_SUPPORT) */
#if !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT)
		&asn_PER_type_NGAP_Paging_eDRX_Cycle_constr_1,
#endif  /* !defined(ASN_DISABLE_UPER_SUPPORT) || !defined(ASN_DISABLE_APER_SUPPORT) */
		NativeEnumerated_constraint
	},
	0, 0,	/* Defined elsewhere */
	&asn_SPC_NGAP_Paging_eDRX_Cycle_specs_1	/* Additional specs */
};

