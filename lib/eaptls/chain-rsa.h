/*
 * Copyright (c) 2016 Thomas Pornin <pornin@bolet.org>
 *
 * Permission is hereby granted, free of charge, to any person obtaining 
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be 
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, 
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "inc/bearssl.h"

/*
 * A sample server certificate chain with a single intermediate CA.
 * Certificate key type: RSA
 * Signing algorithm for both certificates: RSA
 */

static const unsigned char CERT0[] = {
	0x30, 0x82, 0x04, 0x87, 0x30, 0x82, 0x03, 0x6F, 0xA0, 0x03, 0x02, 0x01,
	0x02, 0x02, 0x14, 0x08, 0xAB, 0xEF, 0x29, 0x2F, 0xE4, 0x23, 0x3A, 0xD6,
	0x30, 0x7D, 0x8B, 0x36, 0x46, 0x0A, 0x69, 0x9A, 0xA0, 0x39, 0xF5, 0x30,
	0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
	0x05, 0x00, 0x30, 0x7F, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
	0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x1F, 0x30, 0x1D, 0x06, 0x03, 0x55,
	0x04, 0x08, 0x0C, 0x16, 0x4E, 0x6F, 0x72, 0x74, 0x68, 0x20, 0x52, 0x68,
	0x69, 0x6E, 0x65, 0x2D, 0x57, 0x65, 0x73, 0x74, 0x70, 0x68, 0x61, 0x6C,
	0x69, 0x61, 0x31, 0x0D, 0x30, 0x0B, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C,
	0x04, 0x42, 0x6F, 0x6E, 0x6E, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55,
	0x04, 0x0A, 0x0C, 0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31, 0x0E, 0x30,
	0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x05, 0x73, 0x63, 0x68, 0x75,
	0x65, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7,
	0x0D, 0x01, 0x09, 0x01, 0x16, 0x11, 0x73, 0x63, 0x68, 0x75, 0x65, 0x40,
	0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x30,
	0x1E, 0x17, 0x0D, 0x32, 0x33, 0x30, 0x33, 0x32, 0x38, 0x31, 0x32, 0x33,
	0x38, 0x33, 0x31, 0x5A, 0x17, 0x0D, 0x32, 0x34, 0x30, 0x33, 0x32, 0x37,
	0x31, 0x32, 0x33, 0x38, 0x33, 0x31, 0x5A, 0x30, 0x7F, 0x31, 0x0B, 0x30,
	0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x44, 0x45, 0x31, 0x1F,
	0x30, 0x1D, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x16, 0x4E, 0x6F, 0x72,
	0x74, 0x68, 0x20, 0x52, 0x68, 0x69, 0x6E, 0x65, 0x2D, 0x57, 0x65, 0x73,
	0x74, 0x70, 0x68, 0x61, 0x6C, 0x69, 0x61, 0x31, 0x0D, 0x30, 0x0B, 0x06,
	0x03, 0x55, 0x04, 0x07, 0x0C, 0x04, 0x42, 0x6F, 0x6E, 0x6E, 0x31, 0x0E,
	0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x0A, 0x0C, 0x05, 0x73, 0x63, 0x68,
	0x75, 0x65, 0x31, 0x0E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C,
	0x05, 0x73, 0x63, 0x68, 0x75, 0x65, 0x31, 0x20, 0x30, 0x1E, 0x06, 0x09,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01, 0x16, 0x11, 0x73,
	0x63, 0x68, 0x75, 0x65, 0x40, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65,
	0x2E, 0x63, 0x6F, 0x6D, 0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00, 0x03,
	0x82, 0x01, 0x0F, 0x00, 0x30, 0x82, 0x01, 0x0A, 0x02, 0x82, 0x01, 0x01,
	0x00, 0x93, 0x61, 0xC8, 0x98, 0x00, 0xBD, 0x59, 0x61, 0x92, 0x6D, 0x92,
	0xD8, 0x0D, 0x37, 0x53, 0xA0, 0x17, 0xD7, 0x7C, 0x4B, 0xF7, 0x85, 0xDD,
	0x07, 0xC8, 0x8D, 0x06, 0xB3, 0xB6, 0xCA, 0x3E, 0xC4, 0xC4, 0xF3, 0x60,
	0x23, 0x70, 0x1A, 0x3A, 0x5D, 0x56, 0x91, 0x28, 0x1E, 0xFF, 0x77, 0xEB,
	0x56, 0x46, 0x32, 0xF9, 0xB4, 0x96, 0x7F, 0xD1, 0xBC, 0xF9, 0xC3, 0x67,
	0x7E, 0xDF, 0xEA, 0xFD, 0xAC, 0x36, 0xA6, 0x3B, 0x5D, 0xA5, 0x73, 0x56,
	0x01, 0x6F, 0xBC, 0xE2, 0xB0, 0xC3, 0x2A, 0x7B, 0x0B, 0x2B, 0x48, 0xA4,
	0x9A, 0x4B, 0x23, 0xD1, 0xE2, 0x6E, 0x39, 0x0D, 0x04, 0xB7, 0xDD, 0xD9,
	0xFC, 0x0D, 0xC8, 0xB3, 0x31, 0x4F, 0x20, 0xD8, 0x4C, 0xE5, 0xC1, 0xB1,
	0xB2, 0x60, 0x66, 0x44, 0xB4, 0xA5, 0xDE, 0x29, 0x61, 0x63, 0x4A, 0x1F,
	0x13, 0xDC, 0x26, 0x7B, 0x7A, 0xDD, 0xFA, 0xB6, 0x8F, 0x87, 0xF0, 0x4D,
	0xDE, 0x5F, 0xAF, 0xE6, 0x34, 0x6F, 0x00, 0xA4, 0x3E, 0x9E, 0x14, 0x9B,
	0xBB, 0xD3, 0xB6, 0x92, 0x12, 0x1B, 0x20, 0x5D, 0x02, 0xAB, 0x6F, 0x65,
	0x41, 0xF6, 0x5D, 0x58, 0x1D, 0x23, 0x27, 0xA0, 0x2F, 0x1F, 0xDE, 0x4C,
	0xF9, 0x50, 0x7F, 0x98, 0x77, 0xF5, 0x2D, 0x7D, 0xA7, 0x1C, 0xBF, 0x7D,
	0xA6, 0x50, 0x75, 0x2C, 0x95, 0xEF, 0x33, 0x95, 0x3E, 0x72, 0x0E, 0x98,
	0xBF, 0x8C, 0xB2, 0x3E, 0x16, 0xC4, 0x47, 0x80, 0x5E, 0x99, 0xD5, 0xA8,
	0xA0, 0x6A, 0xFD, 0x0A, 0xED, 0xDD, 0xE1, 0x2E, 0x1C, 0xBD, 0xD8, 0x0F,
	0x43, 0x8B, 0x1D, 0x2C, 0x0C, 0x32, 0x81, 0x51, 0x73, 0x84, 0x9F, 0xE6,
	0x39, 0x02, 0x94, 0xA0, 0xA7, 0x8F, 0x7B, 0x4A, 0x06, 0x0A, 0x6D, 0xAB,
	0xEE, 0x86, 0x4F, 0x2C, 0x27, 0x24, 0x9D, 0xD0, 0xA9, 0x29, 0xDA, 0x10,
	0xF8, 0x5B, 0xA7, 0x81, 0x3F, 0x02, 0x03, 0x01, 0x00, 0x01, 0xA3, 0x81,
	0xFA, 0x30, 0x81, 0xF7, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04,
	0x16, 0x04, 0x14, 0xC1, 0x1A, 0x2C, 0xD9, 0x73, 0xFB, 0x36, 0x45, 0x33,
	0x94, 0xAE, 0xC0, 0xE4, 0xD6, 0x81, 0x11, 0xE8, 0x89, 0x73, 0xDB, 0x30,
	0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
	0xC1, 0x1A, 0x2C, 0xD9, 0x73, 0xFB, 0x36, 0x45, 0x33, 0x94, 0xAE, 0xC0,
	0xE4, 0xD6, 0x81, 0x11, 0xE8, 0x89, 0x73, 0xDB, 0x30, 0x09, 0x06, 0x03,
	0x55, 0x1D, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0B, 0x06, 0x03, 0x55,
	0x1D, 0x0F, 0x04, 0x04, 0x03, 0x02, 0x05, 0xA0, 0x30, 0x6F, 0x06, 0x03,
	0x55, 0x1D, 0x11, 0x04, 0x68, 0x30, 0x66, 0x82, 0x09, 0x73, 0x63, 0x68,
	0x75, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x0D, 0x77, 0x77, 0x77, 0x2E,
	0x73, 0x63, 0x68, 0x75, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x0E, 0x6D,
	0x61, 0x69, 0x6C, 0x2E, 0x73, 0x63, 0x68, 0x75, 0x65, 0x2E, 0x63, 0x6F,
	0x6D, 0x82, 0x0D, 0x66, 0x74, 0x70, 0x2E, 0x73, 0x63, 0x68, 0x75, 0x65,
	0x2E, 0x63, 0x6F, 0x6D, 0x82, 0x09, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68,
	0x6F, 0x73, 0x74, 0x82, 0x15, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x68, 0x6F,
	0x73, 0x74, 0x2E, 0x6C, 0x6F, 0x63, 0x61, 0x6C, 0x64, 0x6F, 0x6D, 0x61,
	0x69, 0x6E, 0x82, 0x09, 0x31, 0x32, 0x37, 0x2E, 0x30, 0x2E, 0x30, 0x2E,
	0x31, 0x30, 0x2C, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42,
	0x01, 0x0D, 0x04, 0x1F, 0x16, 0x1D, 0x4F, 0x70, 0x65, 0x6E, 0x53, 0x53,
	0x4C, 0x20, 0x47, 0x65, 0x6E, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20,
	0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x30,
	0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
	0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00, 0x47, 0x36, 0xF5, 0xD5, 0xD6,
	0x93, 0xA9, 0x42, 0x83, 0x3E, 0x3E, 0xF4, 0x90, 0x84, 0xC8, 0xE5, 0x06,
	0x99, 0xE7, 0xA9, 0xBB, 0x12, 0x2C, 0x51, 0x63, 0x5B, 0x65, 0x23, 0x97,
	0xC4, 0xEB, 0x32, 0x26, 0x8F, 0x7D, 0x66, 0xAF, 0x79, 0x73, 0x34, 0xE0,
	0xC7, 0x5A, 0xD9, 0x3E, 0xD6, 0x41, 0x92, 0xFE, 0x84, 0x81, 0x46, 0x69,
	0xF0, 0x10, 0x18, 0x15, 0x7C, 0xA3, 0x0E, 0x0C, 0x02, 0x22, 0x09, 0x62,
	0x36, 0x06, 0x57, 0xE2, 0x34, 0x5D, 0xBD, 0x56, 0x41, 0x92, 0x95, 0xDD,
	0xCB, 0x4F, 0xEE, 0x6A, 0x5D, 0x56, 0xEA, 0x8B, 0xEB, 0x23, 0xDA, 0x85,
	0xD8, 0xAD, 0xD8, 0xEF, 0x3B, 0x9A, 0xF6, 0x6A, 0x24, 0x0B, 0x5D, 0x81,
	0xDB, 0xC7, 0x79, 0x5A, 0x26, 0xAD, 0xB5, 0x51, 0xDE, 0xC5, 0xE4, 0xBA,
	0xD1, 0xE2, 0xD6, 0x9C, 0xFA, 0xFA, 0x67, 0x98, 0x55, 0xC2, 0x1C, 0xD9,
	0xE4, 0x1A, 0xEF, 0x84, 0x90, 0x60, 0x09, 0xC4, 0xC6, 0x87, 0x2B, 0xFE,
	0xC3, 0xA0, 0x28, 0xF8, 0x2C, 0x15, 0x08, 0x4C, 0x74, 0xD7, 0xA0, 0x78,
	0x7A, 0x46, 0x19, 0x1F, 0x5A, 0xEB, 0xAB, 0x69, 0x55, 0x6C, 0x86, 0x2C,
	0xF8, 0x93, 0x87, 0x8E, 0x07, 0xDF, 0x02, 0xEF, 0xED, 0x48, 0xAF, 0x45,
	0x2D, 0x8D, 0x6E, 0xAF, 0x1D, 0xF2, 0x97, 0x49, 0x8C, 0x15, 0x37, 0xF7,
	0xE9, 0x76, 0x02, 0x80, 0x14, 0xC4, 0x64, 0x15, 0xCB, 0xE2, 0xB3, 0xB9,
	0xAF, 0x8C, 0x9C, 0xD2, 0x34, 0x55, 0xF9, 0x8D, 0x61, 0x4B, 0x67, 0x43,
	0x53, 0x3C, 0x66, 0x78, 0x7B, 0xE1, 0x3A, 0x8D, 0x94, 0xFA, 0x59, 0xB0,
	0x17, 0x5E, 0x15, 0x10, 0x8E, 0x0B, 0xBD, 0xBD, 0xEA, 0x8B, 0xE1, 0x99,
	0x46, 0xB0, 0xF5, 0x44, 0x51, 0xD9, 0xD6, 0x98, 0xF9, 0x36, 0x3B, 0xD6,
	0x56, 0xEA, 0x19, 0x47, 0xC9, 0x85, 0xEA, 0x0D, 0xF0, 0x44, 0x4A
};

static const br_x509_certificate CHAIN[] = {
	{ (unsigned char *)CERT0, sizeof CERT0 }
};

#define CHAIN_LEN   1
