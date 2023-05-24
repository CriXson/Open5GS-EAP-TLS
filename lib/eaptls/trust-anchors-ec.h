#include "inc/bearssl.h"

static const unsigned char TA0_DN[] = {
        0x30, 0x7F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
        0x02, 0x44, 0x45, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x08,
        0x0C, 0x16, 0x4E, 0x6F, 0x72, 0x74, 0x68, 0x20, 0x52, 0x68, 0x69, 0x6E,
        0x65, 0x2D, 0x57, 0x65, 0x73, 0x74, 0x70, 0x68, 0x61, 0x6C, 0x69, 0x61,
        0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x04, 0x42,
        0x6F, 0x6E, 0x6E, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A,
        0x0C, 0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31, 0x0E, 0x30, 0x0C, 0x06,
        0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31,
        0x20, 0x30, 0x1E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
        0x09, 0x01, 0x16, 0x11, 0x73, 0x63, 0x68, 0x75, 0x65, 0x40, 0x65, 0x78,
        0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D
};

static const unsigned char TA0_EC_Q[] = {
        0x04, 0xBC, 0xFE, 0x13, 0xEC, 0x54, 0x5E, 0xFE, 0xC8, 0x10, 0x68, 0x37,
        0x82, 0xB2, 0x5F, 0x22, 0x49, 0x86, 0xDA, 0xA8, 0xF3, 0x49, 0xF8, 0xA9,
        0x6F, 0x43, 0x16, 0x22, 0x0F, 0x6F, 0x6B, 0x19, 0x48, 0xE5, 0x2C, 0x69,
        0x38, 0xD1, 0xBE, 0xAF, 0x58, 0x79, 0x25, 0x87, 0xB9, 0x07, 0xF8, 0x35,
        0xF7, 0xAD, 0x51, 0x1E, 0x5E, 0xC1, 0xBB, 0x2A, 0xC2, 0xBB, 0x24, 0x04,
        0xE4, 0x77, 0x88, 0x13, 0xCA, 0x2D, 0xDF, 0xBB, 0x00, 0xD1, 0x2D, 0x3C,
        0x38, 0xCB, 0xA1, 0xA4, 0xFC, 0x55, 0x93, 0xAD, 0xF9, 0xE6, 0x88, 0x34,
        0xCD, 0xB9, 0x96, 0xF4, 0x8E, 0xBA, 0xA4, 0xE1, 0xAE, 0xA6, 0xDF, 0xF8,
        0xFE
};

static const br_x509_trust_anchor TAs[1] = {
        {
                { (unsigned char *)TA0_DN, sizeof TA0_DN },
                0,
                {
                        BR_KEYTYPE_EC,
                        { .ec = {
                                BR_EC_secp384r1,
                                (unsigned char *)TA0_EC_Q, sizeof TA0_EC_Q,
                        } }
                }
        }
};

#define TAs_NUM   1