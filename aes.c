/*
    Copyright (C) MINZKN.COM
    All rights reserved.
    Author: JAEHYUK CHO <mailto:minzkn@minzkn.com>
*/

#if !defined(__def_sslid_source_aes_c__)
# define __def_sslid_source_aes_c__ "aes.c"

#include "sslid-lib.h"

void *hwport_encrypt_mode_cfb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_mode_cfb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

void *hwport_encrypt_mode_cfb8_for_product_key(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_mode_cfb8_for_product_key(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

void *hwport_encrypt_mode_ofb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_mode_ofb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

void *hwport_encrypt_mode_cbc(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_mode_cbc(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

void *hwport_make_round_key_aes128(void *s_round_key, const void *s_user_key);
void *hwport_make_round_key_aes192(void *s_round_key, const void *s_user_key);
void *hwport_make_round_key_aes256(void *s_round_key, const void *s_user_key);

static void hwport_aes_first_addroundkey(void *s_state, const void *s_text, const void *s_round_key);
static void hwport_aes_addroundkey(void *s_state, const void *s_round_key);
static void hwport_aes_last_addroundkey(void *s_text, const void *s_state, const void *s_round_key);

static void hwport_aes_subbytes_shiftrows(uint8_t *s_state);
static void hwport_aes_subbyte_shiftrows_mixcols(uint8_t *s_state);
static void __hwport_aes_encrypt_block(size_t s_rounds, void *s_cipher_text, const void *s_plain_text, const void *s_round_key);
static void hwport_aes128_encrypt_block(void *s_cipher_text, const void *s_plain_text, const void *s_round_key);
static void hwport_aes192_encrypt_block(void *s_cipher_text, const void *s_plain_text, const void *s_round_key);
static void hwport_aes256_encrypt_block(void *s_cipher_text, const void *s_plain_text, const void *s_round_key);

static void hwport_aes_isubbytes_ishiftrows(uint8_t *s_state);
static void hwport_aes_isubbyte_ishiftrows_imixcols(uint8_t *s_state);
static void __hwport_aes_decrypt_block(size_t s_rounds, void *s_plain_text, const void *s_cipher_text, const void *s_round_key);
static void hwport_aes128_decrypt_block(void *s_plain_text, const void *s_cipher_text, const void *s_round_key);
static void hwport_aes192_decrypt_block(void *s_plain_text, const void *s_cipher_text, const void *s_round_key);
static void hwport_aes256_decrypt_block(void *s_plain_text, const void *s_cipher_text, const void *s_round_key);

void *hwport_encrypt_aes128_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_decrypt_aes128_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_encrypt_aes128_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes128_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_encrypt_aes128_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes128_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_encrypt_aes128_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes128_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

void *hwport_encrypt_aes192_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_decrypt_aes192_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_encrypt_aes192_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes192_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_encrypt_aes192_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes192_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_encrypt_aes192_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes192_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

void *hwport_encrypt_aes256_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_decrypt_aes256_ecb(void *s_data, size_t s_size, const void *s_round_key);
void *hwport_encrypt_aes256_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes256_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_encrypt_aes256_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes256_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_encrypt_aes256_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);
void *hwport_decrypt_aes256_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key);

/* ---- */
    
/* {{{ __hwport_aes_rcon */
static const uint8_t g_hwport_aes_rcon[] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 
    0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 
    0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 
    0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 
    0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 
    0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 
    0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 
    0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 
    0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};
#define __hwport_aes_rcon(m_index) (g_hwport_aes_rcon[m_index])
/* }}} */

/* {{{ __hwport_aes_sbox */
static const uint8_t g_hwport_aes_sbox[] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
#define __hwport_aes_sbox(m_index) (g_hwport_aes_sbox[m_index])
/* }}} */

/* {{{ __hwport_aes_isbox */
static const uint8_t g_hwport_aes_isbox[] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};
#define __hwport_aes_isbox(m_index) (g_hwport_aes_isbox[m_index])
/* }}} */

/* {{{ __hwport_aes_xtime2_sbox */
static const uint8_t g_hwport_aes_xtime2_sbox[] = {
    0xc6, 0xf8, 0xee, 0xf6, 0xff, 0xd6, 0xde, 0x91, 0x60, 0x02, 0xce, 0x56, 0xe7, 0xb5, 0x4d, 0xec,
    0x8f, 0x1f, 0x89, 0xfa, 0xef, 0xb2, 0x8e, 0xfb, 0x41, 0xb3, 0x5f, 0x45, 0x23, 0x53, 0xe4, 0x9b,
    0x75, 0xe1, 0x3d, 0x4c, 0x6c, 0x7e, 0xf5, 0x83, 0x68, 0x51, 0xd1, 0xf9, 0xe2, 0xab, 0x62, 0x2a,
    0x08, 0x95, 0x46, 0x9d, 0x30, 0x37, 0x0a, 0x2f, 0x0e, 0x24, 0x1b, 0xdf, 0xcd, 0x4e, 0x7f, 0xea,
    0x12, 0x1d, 0x58, 0x34, 0x36, 0xdc, 0xb4, 0x5b, 0xa4, 0x76, 0xb7, 0x7d, 0x52, 0xdd, 0x5e, 0x13,
    0xa6, 0xb9, 0x00, 0xc1, 0x40, 0xe3, 0x79, 0xb6, 0xd4, 0x8d, 0x67, 0x72, 0x94, 0x98, 0xb0, 0x85,
    0xbb, 0xc5, 0x4f, 0xed, 0x86, 0x9a, 0x66, 0x11, 0x8a, 0xe9, 0x04, 0xfe, 0xa0, 0x78, 0x25, 0x4b,
    0xa2, 0x5d, 0x80, 0x05, 0x3f, 0x21, 0x70, 0xf1, 0x63, 0x77, 0xaf, 0x42, 0x20, 0xe5, 0xfd, 0xbf,
    0x81, 0x18, 0x26, 0xc3, 0xbe, 0x35, 0x88, 0x2e, 0x93, 0x55, 0xfc, 0x7a, 0xc8, 0xba, 0x32, 0xe6,
    0xc0, 0x19, 0x9e, 0xa3, 0x44, 0x54, 0x3b, 0x0b, 0x8c, 0xc7, 0x6b, 0x28, 0xa7, 0xbc, 0x16, 0xad,
    0xdb, 0x64, 0x74, 0x14, 0x92, 0x0c, 0x48, 0xb8, 0x9f, 0xbd, 0x43, 0xc4, 0x39, 0x31, 0xd3, 0xf2,
    0xd5, 0x8b, 0x6e, 0xda, 0x01, 0xb1, 0x9c, 0x49, 0xd8, 0xac, 0xf3, 0xcf, 0xca, 0xf4, 0x47, 0x10,
    0x6f, 0xf0, 0x4a, 0x5c, 0x38, 0x57, 0x73, 0x97, 0xcb, 0xa1, 0xe8, 0x3e, 0x96, 0x61, 0x0d, 0x0f,
    0xe0, 0x7c, 0x71, 0xcc, 0x90, 0x06, 0xf7, 0x1c, 0xc2, 0x6a, 0xae, 0x69, 0x17, 0x99, 0x3a, 0x27,
    0xd9, 0xeb, 0x2b, 0x22, 0xd2, 0xa9, 0x07, 0x33, 0x2d, 0x3c, 0x15, 0xc9, 0x87, 0xaa, 0x50, 0xa5,
    0x03, 0x59, 0x09, 0x1a, 0x65, 0xd7, 0x84, 0xd0, 0x82, 0x29, 0x5a, 0x1e, 0x7b, 0xa8, 0x6d, 0x2c
};
#define __hwport_aes_xtime2_sbox(m_index) (g_hwport_aes_xtime2_sbox[m_index])
/* }}} */

/* {{{ __hwport_aes_xtime3_sbox */
static const uint8_t g_hwport_aes_xtime3_sbox[] = {
    0xa5, 0x84, 0x99, 0x8d, 0x0d, 0xbd, 0xb1, 0x54, 0x50, 0x03, 0xa9, 0x7d, 0x19, 0x62, 0xe6, 0x9a,
    0x45, 0x9d, 0x40, 0x87, 0x15, 0xeb, 0xc9, 0x0b, 0xec, 0x67, 0xfd, 0xea, 0xbf, 0xf7, 0x96, 0x5b,
    0xc2, 0x1c, 0xae, 0x6a, 0x5a, 0x41, 0x02, 0x4f, 0x5c, 0xf4, 0x34, 0x08, 0x93, 0x73, 0x53, 0x3f,
    0x0c, 0x52, 0x65, 0x5e, 0x28, 0xa1, 0x0f, 0xb5, 0x09, 0x36, 0x9b, 0x3d, 0x26, 0x69, 0xcd, 0x9f,
    0x1b, 0x9e, 0x74, 0x2e, 0x2d, 0xb2, 0xee, 0xfb, 0xf6, 0x4d, 0x61, 0xce, 0x7b, 0x3e, 0x71, 0x97,
    0xf5, 0x68, 0x00, 0x2c, 0x60, 0x1f, 0xc8, 0xed, 0xbe, 0x46, 0xd9, 0x4b, 0xde, 0xd4, 0xe8, 0x4a,
    0x6b, 0x2a, 0xe5, 0x16, 0xc5, 0xd7, 0x55, 0x94, 0xcf, 0x10, 0x06, 0x81, 0xf0, 0x44, 0xba, 0xe3,
    0xf3, 0xfe, 0xc0, 0x8a, 0xad, 0xbc, 0x48, 0x04, 0xdf, 0xc1, 0x75, 0x63, 0x30, 0x1a, 0x0e, 0x6d,
    0x4c, 0x14, 0x35, 0x2f, 0xe1, 0xa2, 0xcc, 0x39, 0x57, 0xf2, 0x82, 0x47, 0xac, 0xe7, 0x2b, 0x95,
    0xa0, 0x98, 0xd1, 0x7f, 0x66, 0x7e, 0xab, 0x83, 0xca, 0x29, 0xd3, 0x3c, 0x79, 0xe2, 0x1d, 0x76,
    0x3b, 0x56, 0x4e, 0x1e, 0xdb, 0x0a, 0x6c, 0xe4, 0x5d, 0x6e, 0xef, 0xa6, 0xa8, 0xa4, 0x37, 0x8b,
    0x32, 0x43, 0x59, 0xb7, 0x8c, 0x64, 0xd2, 0xe0, 0xb4, 0xfa, 0x07, 0x25, 0xaf, 0x8e, 0xe9, 0x18,
    0xd5, 0x88, 0x6f, 0x72, 0x24, 0xf1, 0xc7, 0x51, 0x23, 0x7c, 0x9c, 0x21, 0xdd, 0xdc, 0x86, 0x85,
    0x90, 0x42, 0xc4, 0xaa, 0xd8, 0x05, 0x01, 0x12, 0xa3, 0x5f, 0xf9, 0xd0, 0x91, 0x58, 0x27, 0xb9,
    0x38, 0x13, 0xb3, 0x33, 0xbb, 0x70, 0x89, 0xa7, 0xb6, 0x22, 0x92, 0x20, 0x49, 0xff, 0x78, 0x7a,
    0x8f, 0xf8, 0x80, 0x17, 0xda, 0x31, 0xc6, 0xb8, 0xc3, 0xb0, 0x77, 0x11, 0xcb, 0xfc, 0xd6, 0x3a,
};
#define __hwport_aes_xtime3_sbox(m_index) (g_hwport_aes_xtime3_sbox[m_index])
/* }}} */

/* {{{ __hwport_aes_xtime9 */
static const uint8_t g_hwport_aes_xtime9[] = {
    0x00, 0x09, 0x12, 0x1b, 0x24, 0x2d, 0x36, 0x3f, 0x48, 0x41, 0x5a, 0x53, 0x6c, 0x65, 0x7e, 0x77,
    0x90, 0x99, 0x82, 0x8b, 0xb4, 0xbd, 0xa6, 0xaf, 0xd8, 0xd1, 0xca, 0xc3, 0xfc, 0xf5, 0xee, 0xe7,
    0x3b, 0x32, 0x29, 0x20, 0x1f, 0x16, 0x0d, 0x04, 0x73, 0x7a, 0x61, 0x68, 0x57, 0x5e, 0x45, 0x4c,
    0xab, 0xa2, 0xb9, 0xb0, 0x8f, 0x86, 0x9d, 0x94, 0xe3, 0xea, 0xf1, 0xf8, 0xc7, 0xce, 0xd5, 0xdc,
    0x76, 0x7f, 0x64, 0x6d, 0x52, 0x5b, 0x40, 0x49, 0x3e, 0x37, 0x2c, 0x25, 0x1a, 0x13, 0x08, 0x01,
    0xe6, 0xef, 0xf4, 0xfd, 0xc2, 0xcb, 0xd0, 0xd9, 0xae, 0xa7, 0xbc, 0xb5, 0x8a, 0x83, 0x98, 0x91,
    0x4d, 0x44, 0x5f, 0x56, 0x69, 0x60, 0x7b, 0x72, 0x05, 0x0c, 0x17, 0x1e, 0x21, 0x28, 0x33, 0x3a,
    0xdd, 0xd4, 0xcf, 0xc6, 0xf9, 0xf0, 0xeb, 0xe2, 0x95, 0x9c, 0x87, 0x8e, 0xb1, 0xb8, 0xa3, 0xaa,
    0xec, 0xe5, 0xfe, 0xf7, 0xc8, 0xc1, 0xda, 0xd3, 0xa4, 0xad, 0xb6, 0xbf, 0x80, 0x89, 0x92, 0x9b,
    0x7c, 0x75, 0x6e, 0x67, 0x58, 0x51, 0x4a, 0x43, 0x34, 0x3d, 0x26, 0x2f, 0x10, 0x19, 0x02, 0x0b,
    0xd7, 0xde, 0xc5, 0xcc, 0xf3, 0xfa, 0xe1, 0xe8, 0x9f, 0x96, 0x8d, 0x84, 0xbb, 0xb2, 0xa9, 0xa0,
    0x47, 0x4e, 0x55, 0x5c, 0x63, 0x6a, 0x71, 0x78, 0x0f, 0x06, 0x1d, 0x14, 0x2b, 0x22, 0x39, 0x30,
    0x9a, 0x93, 0x88, 0x81, 0xbe, 0xb7, 0xac, 0xa5, 0xd2, 0xdb, 0xc0, 0xc9, 0xf6, 0xff, 0xe4, 0xed,
    0x0a, 0x03, 0x18, 0x11, 0x2e, 0x27, 0x3c, 0x35, 0x42, 0x4b, 0x50, 0x59, 0x66, 0x6f, 0x74, 0x7d,
    0xa1, 0xa8, 0xb3, 0xba, 0x85, 0x8c, 0x97, 0x9e, 0xe9, 0xe0, 0xfb, 0xf2, 0xcd, 0xc4, 0xdf, 0xd6,
    0x31, 0x38, 0x23, 0x2a, 0x15, 0x1c, 0x07, 0x0e, 0x79, 0x70, 0x6b, 0x62, 0x5d, 0x54, 0x4f, 0x46
};
#define __hwport_aes_xtime9(m_index) (g_hwport_aes_xtime9[m_index])
/* }}} */

/* {{{ __hwport_aes_xtimeb */
static const uint8_t g_hwport_aes_xtimeb[] = {
    0x00, 0x0b, 0x16, 0x1d, 0x2c, 0x27, 0x3a, 0x31, 0x58, 0x53, 0x4e, 0x45, 0x74, 0x7f, 0x62, 0x69,
    0xb0, 0xbb, 0xa6, 0xad, 0x9c, 0x97, 0x8a, 0x81, 0xe8, 0xe3, 0xfe, 0xf5, 0xc4, 0xcf, 0xd2, 0xd9,
    0x7b, 0x70, 0x6d, 0x66, 0x57, 0x5c, 0x41, 0x4a, 0x23, 0x28, 0x35, 0x3e, 0x0f, 0x04, 0x19, 0x12,
    0xcb, 0xc0, 0xdd, 0xd6, 0xe7, 0xec, 0xf1, 0xfa, 0x93, 0x98, 0x85, 0x8e, 0xbf, 0xb4, 0xa9, 0xa2,
    0xf6, 0xfd, 0xe0, 0xeb, 0xda, 0xd1, 0xcc, 0xc7, 0xae, 0xa5, 0xb8, 0xb3, 0x82, 0x89, 0x94, 0x9f,
    0x46, 0x4d, 0x50, 0x5b, 0x6a, 0x61, 0x7c, 0x77, 0x1e, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2f,
    0x8d, 0x86, 0x9b, 0x90, 0xa1, 0xaa, 0xb7, 0xbc, 0xd5, 0xde, 0xc3, 0xc8, 0xf9, 0xf2, 0xef, 0xe4,
    0x3d, 0x36, 0x2b, 0x20, 0x11, 0x1a, 0x07, 0x0c, 0x65, 0x6e, 0x73, 0x78, 0x49, 0x42, 0x5f, 0x54,
    0xf7, 0xfc, 0xe1, 0xea, 0xdb, 0xd0, 0xcd, 0xc6, 0xaf, 0xa4, 0xb9, 0xb2, 0x83, 0x88, 0x95, 0x9e,
    0x47, 0x4c, 0x51, 0x5a, 0x6b, 0x60, 0x7d, 0x76, 0x1f, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2e,
    0x8c, 0x87, 0x9a, 0x91, 0xa0, 0xab, 0xb6, 0xbd, 0xd4, 0xdf, 0xc2, 0xc9, 0xf8, 0xf3, 0xee, 0xe5,
    0x3c, 0x37, 0x2a, 0x21, 0x10, 0x1b, 0x06, 0x0d, 0x64, 0x6f, 0x72, 0x79, 0x48, 0x43, 0x5e, 0x55,
    0x01, 0x0a, 0x17, 0x1c, 0x2d, 0x26, 0x3b, 0x30, 0x59, 0x52, 0x4f, 0x44, 0x75, 0x7e, 0x63, 0x68,
    0xb1, 0xba, 0xa7, 0xac, 0x9d, 0x96, 0x8b, 0x80, 0xe9, 0xe2, 0xff, 0xf4, 0xc5, 0xce, 0xd3, 0xd8,
    0x7a, 0x71, 0x6c, 0x67, 0x56, 0x5d, 0x40, 0x4b, 0x22, 0x29, 0x34, 0x3f, 0x0e, 0x05, 0x18, 0x13,
    0xca, 0xc1, 0xdc, 0xd7, 0xe6, 0xed, 0xf0, 0xfb, 0x92, 0x99, 0x84, 0x8f, 0xbe, 0xb5, 0xa8, 0xa3
};
#define __hwport_aes_xtimeb(m_index) (g_hwport_aes_xtimeb[m_index])
/* }}} */

/* {{{ __hwport_aes_xtimed */
static const uint8_t g_hwport_aes_xtimed[] = {
    0x00, 0x0d, 0x1a, 0x17, 0x34, 0x39, 0x2e, 0x23, 0x68, 0x65, 0x72, 0x7f, 0x5c, 0x51, 0x46, 0x4b,
    0xd0, 0xdd, 0xca, 0xc7, 0xe4, 0xe9, 0xfe, 0xf3, 0xb8, 0xb5, 0xa2, 0xaf, 0x8c, 0x81, 0x96, 0x9b,
    0xbb, 0xb6, 0xa1, 0xac, 0x8f, 0x82, 0x95, 0x98, 0xd3, 0xde, 0xc9, 0xc4, 0xe7, 0xea, 0xfd, 0xf0,
    0x6b, 0x66, 0x71, 0x7c, 0x5f, 0x52, 0x45, 0x48, 0x03, 0x0e, 0x19, 0x14, 0x37, 0x3a, 0x2d, 0x20,
    0x6d, 0x60, 0x77, 0x7a, 0x59, 0x54, 0x43, 0x4e, 0x05, 0x08, 0x1f, 0x12, 0x31, 0x3c, 0x2b, 0x26,
    0xbd, 0xb0, 0xa7, 0xaa, 0x89, 0x84, 0x93, 0x9e, 0xd5, 0xd8, 0xcf, 0xc2, 0xe1, 0xec, 0xfb, 0xf6,
    0xd6, 0xdb, 0xcc, 0xc1, 0xe2, 0xef, 0xf8, 0xf5, 0xbe, 0xb3, 0xa4, 0xa9, 0x8a, 0x87, 0x90, 0x9d,
    0x06, 0x0b, 0x1c, 0x11, 0x32, 0x3f, 0x28, 0x25, 0x6e, 0x63, 0x74, 0x79, 0x5a, 0x57, 0x40, 0x4d,
    0xda, 0xd7, 0xc0, 0xcd, 0xee, 0xe3, 0xf4, 0xf9, 0xb2, 0xbf, 0xa8, 0xa5, 0x86, 0x8b, 0x9c, 0x91,
    0x0a, 0x07, 0x10, 0x1d, 0x3e, 0x33, 0x24, 0x29, 0x62, 0x6f, 0x78, 0x75, 0x56, 0x5b, 0x4c, 0x41,
    0x61, 0x6c, 0x7b, 0x76, 0x55, 0x58, 0x4f, 0x42, 0x09, 0x04, 0x13, 0x1e, 0x3d, 0x30, 0x27, 0x2a,
    0xb1, 0xbc, 0xab, 0xa6, 0x85, 0x88, 0x9f, 0x92, 0xd9, 0xd4, 0xc3, 0xce, 0xed, 0xe0, 0xf7, 0xfa,
    0xb7, 0xba, 0xad, 0xa0, 0x83, 0x8e, 0x99, 0x94, 0xdf, 0xd2, 0xc5, 0xc8, 0xeb, 0xe6, 0xf1, 0xfc,
    0x67, 0x6a, 0x7d, 0x70, 0x53, 0x5e, 0x49, 0x44, 0x0f, 0x02, 0x15, 0x18, 0x3b, 0x36, 0x21, 0x2c,
    0x0c, 0x01, 0x16, 0x1b, 0x38, 0x35, 0x22, 0x2f, 0x64, 0x69, 0x7e, 0x73, 0x50, 0x5d, 0x4a, 0x47,
    0xdc, 0xd1, 0xc6, 0xcb, 0xe8, 0xe5, 0xf2, 0xff, 0xb4, 0xb9, 0xae, 0xa3, 0x80, 0x8d, 0x9a, 0x97
};
#define __hwport_aes_xtimed(m_index) (g_hwport_aes_xtimed[m_index])
/* }}} */

/* {{{ __hwport_aes_xtimee */
static const uint8_t g_hwport_aes_xtimee[] = {
    0x00, 0x0e, 0x1c, 0x12, 0x38, 0x36, 0x24, 0x2a, 0x70, 0x7e, 0x6c, 0x62, 0x48, 0x46, 0x54, 0x5a,
    0xe0, 0xee, 0xfc, 0xf2, 0xd8, 0xd6, 0xc4, 0xca, 0x90, 0x9e, 0x8c, 0x82, 0xa8, 0xa6, 0xb4, 0xba,
    0xdb, 0xd5, 0xc7, 0xc9, 0xe3, 0xed, 0xff, 0xf1, 0xab, 0xa5, 0xb7, 0xb9, 0x93, 0x9d, 0x8f, 0x81,
    0x3b, 0x35, 0x27, 0x29, 0x03, 0x0d, 0x1f, 0x11, 0x4b, 0x45, 0x57, 0x59, 0x73, 0x7d, 0x6f, 0x61,
    0xad, 0xa3, 0xb1, 0xbf, 0x95, 0x9b, 0x89, 0x87, 0xdd, 0xd3, 0xc1, 0xcf, 0xe5, 0xeb, 0xf9, 0xf7,
    0x4d, 0x43, 0x51, 0x5f, 0x75, 0x7b, 0x69, 0x67, 0x3d, 0x33, 0x21, 0x2f, 0x05, 0x0b, 0x19, 0x17,
    0x76, 0x78, 0x6a, 0x64, 0x4e, 0x40, 0x52, 0x5c, 0x06, 0x08, 0x1a, 0x14, 0x3e, 0x30, 0x22, 0x2c,
    0x96, 0x98, 0x8a, 0x84, 0xae, 0xa0, 0xb2, 0xbc, 0xe6, 0xe8, 0xfa, 0xf4, 0xde, 0xd0, 0xc2, 0xcc,
    0x41, 0x4f, 0x5d, 0x53, 0x79, 0x77, 0x65, 0x6b, 0x31, 0x3f, 0x2d, 0x23, 0x09, 0x07, 0x15, 0x1b,
    0xa1, 0xaf, 0xbd, 0xb3, 0x99, 0x97, 0x85, 0x8b, 0xd1, 0xdf, 0xcd, 0xc3, 0xe9, 0xe7, 0xf5, 0xfb,
    0x9a, 0x94, 0x86, 0x88, 0xa2, 0xac, 0xbe, 0xb0, 0xea, 0xe4, 0xf6, 0xf8, 0xd2, 0xdc, 0xce, 0xc0,
    0x7a, 0x74, 0x66, 0x68, 0x42, 0x4c, 0x5e, 0x50, 0x0a, 0x04, 0x16, 0x18, 0x32, 0x3c, 0x2e, 0x20,
    0xec, 0xe2, 0xf0, 0xfe, 0xd4, 0xda, 0xc8, 0xc6, 0x9c, 0x92, 0x80, 0x8e, 0xa4, 0xaa, 0xb8, 0xb6,
    0x0c, 0x02, 0x10, 0x1e, 0x34, 0x3a, 0x28, 0x26, 0x7c, 0x72, 0x60, 0x6e, 0x44, 0x4a, 0x58, 0x56,
    0x37, 0x39, 0x2b, 0x25, 0x0f, 0x01, 0x13, 0x1d, 0x47, 0x49, 0x5b, 0x55, 0x7f, 0x71, 0x63, 0x6d,
    0xd7, 0xd9, 0xcb, 0xc5, 0xef, 0xe1, 0xf3, 0xfd, 0xa7, 0xa9, 0xbb, 0xb5, 0x9f, 0x91, 0x83, 0x8d
};
#define __hwport_aes_xtimee(m_index) (g_hwport_aes_xtimee[m_index])
/* }}} */

/* ---- */

void *hwport_encrypt_mode_cfb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    size_t s_offset;
    uint8_t s_cipher_byte;

    uint8_t s_iv_buffer_local[ 32 ];
    void *s_iv_buffer;
    
    if(s_block_size > sizeof(s_iv_buffer_local)) {
        s_iv_buffer = malloc(s_block_size);
        if(s_iv_buffer == ((void *)0)) { /* ERROR : not enough memory ! */
            return((void *)0);
        }
    }
    else {
        s_iv_buffer = (void *)(&s_iv_buffer_local[0]);
    }

    for(s_offset = (size_t)0u;s_offset < s_size;s_offset++) {
        (void)memcpy(s_iv_buffer, s_initial_vector, s_block_size);

        /* encrypt initial vector to shift register */
        (*s_handler)(s_iv_buffer, s_block_size, s_round_key);

        /* XOR stream with shift register */
        s_cipher_byte = hwport_peek_uint8(s_data, s_offset) ^ hwport_peek_uint8(s_iv_buffer, 0);
        hwport_poke_uint8(s_data, s_offset, s_cipher_byte);

        /* shift register */
        (void)memmove(
            s_initial_vector,
            hwport_peek(s_initial_vector, 1),
            s_block_size - ((size_t)1u)
        );
        hwport_poke_uint8(s_initial_vector, s_block_size - ((size_t)1u), s_cipher_byte);
    }

    if(s_block_size > sizeof(s_iv_buffer_local)) {
        free(s_iv_buffer);
    }

    return(s_data);
}

void *hwport_decrypt_mode_cfb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    size_t s_offset;
    uint8_t s_cipher_byte;
    uint8_t s_plain_byte;

    uint8_t s_iv_buffer_local[ 32 ];
    void *s_iv_buffer;
    
    if(s_block_size > sizeof(s_iv_buffer_local)) {
        s_iv_buffer = malloc(s_block_size);
        if(s_iv_buffer == ((void *)0)) { /* ERROR : not enough memory ! */
            return((void *)0);
        }
    }
    else {
        s_iv_buffer = (void *)(&s_iv_buffer_local[0]);
    }

    for(s_offset = (size_t)0u;s_offset < s_size;s_offset++) {
        (void)memcpy(s_iv_buffer, s_initial_vector, s_block_size);

        /* encrypt initial vector to shift register */
        (*s_handler)(s_iv_buffer, s_block_size, s_round_key);

        /* XOR stream with shift register */
        s_cipher_byte = hwport_peek_uint8(s_data, s_offset);
        s_plain_byte = s_cipher_byte ^ hwport_peek_uint8(s_iv_buffer, 0);
        hwport_poke_uint8(s_data, s_offset, s_plain_byte);

        /* shift register */
        (void)memmove(
            s_initial_vector,
            hwport_peek(s_initial_vector, 1),
            s_block_size - ((size_t)1u)
        );
        hwport_poke_uint8(s_initial_vector, s_block_size - ((size_t)1u), s_cipher_byte);
    }

    if(s_block_size > sizeof(s_iv_buffer_local)) {
        free(s_iv_buffer);
    }

    return(s_data);
}


void *hwport_encrypt_mode_cfb8_for_product_key(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    size_t s_offset;
    uint8_t s_cipher_byte;

    for(s_offset = (size_t)0u;s_offset < s_size;s_offset++) {
        /* encrypt initial vector to shift register */
        (*s_handler)(s_initial_vector, s_block_size, s_round_key);

        /* XOR stream with shift register */
        s_cipher_byte = hwport_peek_uint8(s_data, s_offset) ^ hwport_peek_uint8(s_initial_vector, 0);
        hwport_poke_uint8(s_data, s_offset, s_cipher_byte);

        /* shift register */
        (void)memmove(
            s_initial_vector,
            hwport_peek(s_initial_vector, 1),
            s_block_size - ((size_t)1u)
        );
        hwport_poke_uint8(s_initial_vector, s_block_size - ((size_t)1u), s_cipher_byte);
    }

    return(s_data);
}

void *hwport_decrypt_mode_cfb8_for_product_key(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    size_t s_offset;
    uint8_t s_cipher_byte;
    uint8_t s_plain_byte;

    for(s_offset = (size_t)0u;s_offset < s_size;s_offset++) {
        /* encrypt initial vector to shift register */
        (*s_handler)(s_initial_vector, s_block_size, s_round_key);

        /* XOR stream with shift register */
        s_cipher_byte = hwport_peek_uint8(s_data, s_offset);
        s_plain_byte = s_cipher_byte ^ hwport_peek_uint8(s_initial_vector, 0);
        hwport_poke_uint8(s_data, s_offset, s_plain_byte);

        /* shift register */
        (void)memmove(
            s_initial_vector,
            hwport_peek(s_initial_vector, 1),
            s_block_size - ((size_t)1u)
        );
        hwport_poke_uint8(s_initial_vector, s_block_size - ((size_t)1u), s_cipher_byte);
    }

    return(s_data);
}

void *hwport_encrypt_mode_ofb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    size_t s_offset;
    uint8_t s_initial_byte;
    uint8_t s_cipher_byte;

    for(s_offset = (size_t)0u;s_offset < s_size;s_offset++) {
        /* encrypt initial vector to shift register */
        (*s_handler)(s_initial_vector, s_block_size, s_round_key);

        /* XOR stream with shift register */
        s_initial_byte = hwport_peek_uint8(s_initial_vector, 0);
        s_cipher_byte = hwport_peek_uint8(s_data, s_offset) ^ s_initial_byte;
        hwport_poke_uint8(s_data, s_offset, s_cipher_byte);

        /* shift register */
        (void)memmove(
            s_initial_vector,
            hwport_peek(s_initial_vector, 1),
            s_block_size - ((size_t)1u)
        );
        hwport_poke_uint8(s_initial_vector, s_block_size - ((size_t)1u), s_initial_byte);
    }

    return(s_data);
}

void *hwport_decrypt_mode_ofb8(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_ofb8(s_handler, s_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_mode_cbc(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    size_t s_offset;
    size_t s_xor_offset;
    uint8_t *s_iv_uint8_ptr;
    uint8_t *s_data_uint8_ptr;

    s_iv_uint8_ptr = (uint8_t *)s_initial_vector;
    for(s_offset = (size_t)0u;s_offset < s_size;s_offset += s_block_size) {
        s_data_uint8_ptr = hwport_peek_f(uint8_t *, s_data, s_offset);

        /* Plain text ^= Initialization Vector (IV) */
        for(s_xor_offset = (size_t)0u;s_xor_offset < s_block_size;s_xor_offset++) {
            s_data_uint8_ptr[s_xor_offset] ^= s_iv_uint8_ptr[s_xor_offset];
        }

        /* encrypt */
        (*s_handler)((void *)(&s_data_uint8_ptr[0]), s_block_size, s_round_key);

        /* Initialization Vector (IV) update */
        (void)memcpy((void *)(&s_iv_uint8_ptr[0]), (const void *)(&s_data_uint8_ptr[0]), s_block_size);
    }

    return(s_data);
}

void *hwport_decrypt_mode_cbc(hwport_encrypt_handler_t s_handler, size_t s_block_size, void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    size_t s_offset;
    size_t s_xor_offset;
    uint8_t s_iv_uint8[ 64 ];
    uint8_t *s_iv_uint8_ptr;
    uint8_t *s_data_uint8_ptr;

    if(s_block_size <= sizeof(s_iv_uint8)) {
        s_iv_uint8_ptr = (uint8_t *)(&s_iv_uint8[0]);
    }
    else {
        s_iv_uint8_ptr = (uint8_t *)malloc(s_block_size);
        if(s_iv_uint8_ptr == ((uint8_t *)0)) {
            return((void *)0);
        }
    }
    for(s_offset = (size_t)0u;s_offset < s_size;s_offset += s_block_size) {
        s_data_uint8_ptr = hwport_peek_f(uint8_t *, s_data, s_offset);
        (void)memcpy((void *)(&s_iv_uint8_ptr[0]), (const void *)(&s_data_uint8_ptr[0]), s_block_size);

        /* decrypt */
        (*s_handler)((void *)(&s_data_uint8_ptr[0]), s_block_size, s_round_key);

        /* Plain text ^= Initialization Vector (IV) */
        for(s_xor_offset = (size_t)0u;s_xor_offset < s_block_size;s_xor_offset++) {
            s_data_uint8_ptr[s_xor_offset] ^= hwport_peek_uint8(s_initial_vector, s_xor_offset);
        }
        (void)memcpy((void *)s_initial_vector, (const void *)(&s_iv_uint8_ptr[0]), s_block_size);
    }

    /* mem wipe */
    (void)memset((void *)(&s_iv_uint8_ptr[0]), 0, s_block_size);

    if(s_block_size > sizeof(s_iv_uint8)) {
        free((void *)s_iv_uint8_ptr);
    }

    return(s_data);
}

/* ---- */

void *hwport_make_round_key_aes128(void *s_round_key, const void *s_user_key)
{
    uint8_t s_key_sched[4];
    uint8_t s_temp;

    size_t s_offset;

    (void)memcpy(s_round_key, s_user_key, (size_t)def_hwport_aes128_user_key_size);

    for(s_offset = (size_t)def_hwport_aes128_user_key_size;s_offset < def_hwport_aes128_round_key_size;s_offset += (size_t)4u) {
        s_key_sched[0] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)4u));
        s_key_sched[1] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)3u));
        s_key_sched[2] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)2u));
        s_key_sched[3] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)1u));

        /* Every four blocks (of four bytes), do a complex calculation */
        if ((s_offset % ((size_t)def_hwport_aes128_user_key_size)) == ((size_t)0u)) { /* schedule core */
            s_temp = s_key_sched[0];
            s_key_sched[0] = __hwport_aes_sbox(s_key_sched[1]) ^ __hwport_aes_rcon(s_offset / ((size_t)def_hwport_aes128_user_key_size));
            s_key_sched[1] = __hwport_aes_sbox(s_key_sched[2]);
            s_key_sched[2] = __hwport_aes_sbox(s_key_sched[3]);
            s_key_sched[3] = __hwport_aes_sbox(s_temp);
        }

        hwport_poke_uint8(s_round_key, s_offset + ((size_t)0u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)def_hwport_aes128_user_key_size)) ^ s_key_sched[0]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)1u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes128_user_key_size - 1))) ^ s_key_sched[1]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)2u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes128_user_key_size - 2))) ^ s_key_sched[2]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)3u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes128_user_key_size - 3))) ^ s_key_sched[3]);
    }

    return(s_round_key);
}

void *hwport_make_round_key_aes192(void *s_round_key, const void *s_user_key)
{
    uint8_t s_key_sched[4];
    uint8_t s_temp;

    size_t s_offset;

    (void)memcpy(s_round_key, s_user_key, (size_t)def_hwport_aes192_user_key_size);

    for(s_offset = (size_t)def_hwport_aes192_user_key_size;s_offset < def_hwport_aes192_round_key_size;s_offset += (size_t)4u) {
        s_key_sched[0] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)4u));
        s_key_sched[1] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)3u));
        s_key_sched[2] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)2u));
        s_key_sched[3] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)1u));

        /* Every six sets, do a complex calculation */
        if ((s_offset % ((size_t)def_hwport_aes192_user_key_size)) == ((size_t)0u)) { /* schedule core */
            s_temp = s_key_sched[0];
            s_key_sched[0] = __hwport_aes_sbox(s_key_sched[1]) ^ __hwport_aes_rcon(s_offset / ((size_t)def_hwport_aes192_user_key_size));
            s_key_sched[1] = __hwport_aes_sbox(s_key_sched[2]);
            s_key_sched[2] = __hwport_aes_sbox(s_key_sched[3]);
            s_key_sched[3] = __hwport_aes_sbox(s_temp);
        }

        hwport_poke_uint8(s_round_key, s_offset + ((size_t)0u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)def_hwport_aes192_user_key_size)) ^ s_key_sched[0]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)1u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes192_user_key_size - 1))) ^ s_key_sched[1]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)2u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes192_user_key_size - 2))) ^ s_key_sched[2]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)3u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes192_user_key_size - 3))) ^ s_key_sched[3]);
    }

    return(s_round_key);
}

void *hwport_make_round_key_aes256(void *s_round_key, const void *s_user_key)
{
    uint8_t s_key_sched[4];
    uint8_t s_temp;

    size_t s_offset;

    (void)memcpy(s_round_key, s_user_key, (size_t)def_hwport_aes256_user_key_size);

    for(s_offset = (size_t)def_hwport_aes256_user_key_size;s_offset < def_hwport_aes256_round_key_size;s_offset += (size_t)4u) {
        s_key_sched[0] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)4u));
        s_key_sched[1] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)3u));
        s_key_sched[2] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)2u));
        s_key_sched[3] = hwport_peek_uint8(s_round_key, s_offset - ((size_t)1u));

        if ((s_offset % ((size_t)def_hwport_aes256_user_key_size)) == ((size_t)0u)) { /* schedule core */
            s_temp = s_key_sched[0];
            s_key_sched[0] = __hwport_aes_sbox(s_key_sched[1]) ^ __hwport_aes_rcon(s_offset / ((size_t)def_hwport_aes256_user_key_size));
            s_key_sched[1] = __hwport_aes_sbox(s_key_sched[2]);
            s_key_sched[2] = __hwport_aes_sbox(s_key_sched[3]);
            s_key_sched[3] = __hwport_aes_sbox(s_temp);
        }
        
	if ((s_offset % ((size_t)def_hwport_aes256_user_key_size)) == ((size_t)16u)) { /* For 256-bit keys, we add an extra sbox to the calculation  */
            s_key_sched[0] = __hwport_aes_sbox(s_key_sched[0]);
            s_key_sched[1] = __hwport_aes_sbox(s_key_sched[1]);
            s_key_sched[2] = __hwport_aes_sbox(s_key_sched[2]);
            s_key_sched[3] = __hwport_aes_sbox(s_key_sched[3]);
        }

        hwport_poke_uint8(s_round_key, s_offset + ((size_t)0u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)def_hwport_aes256_user_key_size)) ^ s_key_sched[0]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)1u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes256_user_key_size - 1))) ^ s_key_sched[1]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)2u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes256_user_key_size - 2))) ^ s_key_sched[2]);
        hwport_poke_uint8(s_round_key, s_offset + ((size_t)3u), hwport_peek_uint8(s_round_key, s_offset - ((size_t)(def_hwport_aes256_user_key_size - 3))) ^ s_key_sched[3]);
    }

    return(s_round_key);
}

static void hwport_aes_first_addroundkey(void *s_state, const void *s_text, const void *s_round_key)
{
    size_t s_offset;

    for(s_offset = (size_t)0u;s_offset < ((size_t)def_hwport_aes_block_size);++s_offset) {
        hwport_poke_uint8(s_state, s_offset, hwport_peek_uint8(s_text, s_offset) ^ hwport_peek_uint8(s_round_key, s_offset));
    }
}

static void hwport_aes_addroundkey(void *s_state, const void *s_round_key)
{
    size_t s_offset;

    for(s_offset = (size_t)0u;s_offset < ((size_t)def_hwport_aes_block_size);++s_offset) {
        hwport_poke_uint8(s_state, s_offset, hwport_peek_uint8(s_state, s_offset) ^ hwport_peek_uint8(s_round_key, s_offset));
    }
}

static void hwport_aes_last_addroundkey(void *s_text, const void *s_state, const void *s_round_key)
{
    size_t s_offset;

    for(s_offset = (size_t)0u;s_offset < ((size_t)def_hwport_aes_block_size);++s_offset) {
        hwport_poke_uint8(s_text, s_offset, hwport_peek_uint8(s_state, s_offset) ^ hwport_peek_uint8(s_round_key, s_offset));
    }
}

static void hwport_aes_subbytes_shiftrows(uint8_t *s_state)
{
    uint8_t s_temp;

    s_state[0] = __hwport_aes_sbox(s_state[0]);
    s_state[4] = __hwport_aes_sbox(s_state[4]);
    s_state[8] = __hwport_aes_sbox(s_state[8]);
    s_state[12] = __hwport_aes_sbox(s_state[12]);

    s_temp = s_state[1];
    s_state[1] = __hwport_aes_sbox(s_state[5]);
    s_state[5] = __hwport_aes_sbox(s_state[9]);
    s_state[9] = __hwport_aes_sbox(s_state[13]);
    s_state[13] = __hwport_aes_sbox(s_temp);

    s_temp = s_state[2];
    s_state[2] = __hwport_aes_sbox(s_state[10]);
    s_state[10] = __hwport_aes_sbox(s_temp);
    s_temp = s_state[6];
    s_state[6] = __hwport_aes_sbox(s_state[14]);
    s_state[14] = __hwport_aes_sbox(s_temp);

    s_temp = s_state[3];
    s_state[3] = __hwport_aes_sbox(s_state[15]);
    s_state[15] = __hwport_aes_sbox(s_state[11]);
    s_state[11] = __hwport_aes_sbox(s_state[7]);
    s_state[7] = __hwport_aes_sbox(s_temp);
}

static void hwport_aes_subbyte_shiftrows_mixcols(uint8_t *s_state)
{
    uint8_t s_temp[def_hwport_aes_block_size];

    (void)memcpy((void *)(&s_temp[0]), (const void *)s_state, (size_t)def_hwport_aes_block_size);

    s_state[0] = __hwport_aes_xtime2_sbox(s_temp[0]) ^ __hwport_aes_xtime3_sbox(s_temp[5]) ^ __hwport_aes_sbox(s_temp[10]) ^ __hwport_aes_sbox(s_temp[15]);
    s_state[1] = __hwport_aes_sbox(s_temp[0]) ^ __hwport_aes_xtime2_sbox(s_temp[5]) ^ __hwport_aes_xtime3_sbox(s_temp[10]) ^ __hwport_aes_sbox(s_temp[15]);
    s_state[2] = __hwport_aes_sbox(s_temp[0]) ^ __hwport_aes_sbox(s_temp[5]) ^ __hwport_aes_xtime2_sbox(s_temp[10]) ^ __hwport_aes_xtime3_sbox(s_temp[15]);
    s_state[3] = __hwport_aes_xtime3_sbox(s_temp[0]) ^ __hwport_aes_sbox(s_temp[5]) ^ __hwport_aes_sbox(s_temp[10]) ^ __hwport_aes_xtime2_sbox(s_temp[15]);

    s_state[4] = __hwport_aes_xtime2_sbox(s_temp[4]) ^ __hwport_aes_xtime3_sbox(s_temp[9]) ^ __hwport_aes_sbox(s_temp[14]) ^ __hwport_aes_sbox(s_temp[3]);
    s_state[5] = __hwport_aes_sbox(s_temp[4]) ^ __hwport_aes_xtime2_sbox(s_temp[9]) ^ __hwport_aes_xtime3_sbox(s_temp[14]) ^ __hwport_aes_sbox(s_temp[3]);
    s_state[6] = __hwport_aes_sbox(s_temp[4]) ^ __hwport_aes_sbox(s_temp[9]) ^ __hwport_aes_xtime2_sbox(s_temp[14]) ^ __hwport_aes_xtime3_sbox(s_temp[3]);
    s_state[7] = __hwport_aes_xtime3_sbox(s_temp[4]) ^ __hwport_aes_sbox(s_temp[9]) ^ __hwport_aes_sbox(s_temp[14]) ^ __hwport_aes_xtime2_sbox(s_temp[3]);

    s_state[8] = __hwport_aes_xtime2_sbox(s_temp[8]) ^ __hwport_aes_xtime3_sbox(s_temp[13]) ^ __hwport_aes_sbox(s_temp[2]) ^ __hwport_aes_sbox(s_temp[7]);
    s_state[9] = __hwport_aes_sbox(s_temp[8]) ^ __hwport_aes_xtime2_sbox(s_temp[13]) ^ __hwport_aes_xtime3_sbox(s_temp[2]) ^ __hwport_aes_sbox(s_temp[7]);
    s_state[10] = __hwport_aes_sbox(s_temp[8]) ^ __hwport_aes_sbox(s_temp[13]) ^ __hwport_aes_xtime2_sbox(s_temp[2]) ^ __hwport_aes_xtime3_sbox(s_temp[7]);
    s_state[11] = __hwport_aes_xtime3_sbox(s_temp[8]) ^ __hwport_aes_sbox(s_temp[13]) ^ __hwport_aes_sbox(s_temp[2]) ^ __hwport_aes_xtime2_sbox(s_temp[7]);

    s_state[12] = __hwport_aes_xtime2_sbox(s_temp[12]) ^ __hwport_aes_xtime3_sbox(s_temp[1]) ^ __hwport_aes_sbox(s_temp[6]) ^ __hwport_aes_sbox(s_temp[11]);
    s_state[13] = __hwport_aes_sbox(s_temp[12]) ^ __hwport_aes_xtime2_sbox(s_temp[1]) ^ __hwport_aes_xtime3_sbox(s_temp[6]) ^ __hwport_aes_sbox(s_temp[11]);
    s_state[14] = __hwport_aes_sbox(s_temp[12]) ^ __hwport_aes_sbox(s_temp[1]) ^ __hwport_aes_xtime2_sbox(s_temp[6]) ^ __hwport_aes_xtime3_sbox(s_temp[11]);
    s_state[15] = __hwport_aes_xtime3_sbox(s_temp[12]) ^ __hwport_aes_sbox(s_temp[1]) ^ __hwport_aes_sbox(s_temp[6]) ^ __hwport_aes_xtime2_sbox(s_temp[11]);
}

static void __hwport_aes_encrypt_block(size_t s_rounds, void *s_cipher_text, const void *s_plain_text, const void *s_round_key)
{
    uint8_t s_state[ def_hwport_aes_block_size ];

    size_t s_offset;

    hwport_aes_first_addroundkey((void *)(&s_state[0]), (const void *)s_plain_text, (const void *)s_round_key);

    for(s_offset = (size_t)1u;s_offset < s_rounds;++s_offset) {
        hwport_aes_subbyte_shiftrows_mixcols((uint8_t *)(&s_state[0]));
        hwport_aes_addroundkey((void *)(&s_state[0]), hwport_peek_const(s_round_key, s_offset * ((size_t)def_hwport_aes_block_size)));
    }

    hwport_aes_subbytes_shiftrows((uint8_t *)(&s_state[0]));
    hwport_aes_last_addroundkey((void *)s_cipher_text, (const void *)(&s_state[0]), hwport_peek_const(s_round_key, s_rounds * ((size_t)def_hwport_aes_block_size)));
}

static void hwport_aes128_encrypt_block(void *s_cipher_text, const void *s_plain_text, const void *s_round_key)
{
    __hwport_aes_encrypt_block((size_t)def_hwport_aes128_rounds, s_cipher_text, s_plain_text, s_round_key);
}

static void hwport_aes192_encrypt_block(void *s_cipher_text, const void *s_plain_text, const void *s_round_key)
{
    __hwport_aes_encrypt_block((size_t)def_hwport_aes192_rounds, s_cipher_text, s_plain_text, s_round_key);
}

static void hwport_aes256_encrypt_block(void *s_cipher_text, const void *s_plain_text, const void *s_round_key)
{
    __hwport_aes_encrypt_block((size_t)def_hwport_aes256_rounds, s_cipher_text, s_plain_text, s_round_key);
}

static void hwport_aes_isubbytes_ishiftrows(uint8_t *s_state)
{
    uint8_t s_temp;

    s_state[0] = __hwport_aes_isbox(s_state[0]);
    s_state[4] = __hwport_aes_isbox(s_state[4]);
    s_state[8] = __hwport_aes_isbox(s_state[8]);
    s_state[12] = __hwport_aes_isbox(s_state[12]);

    s_temp = s_state[13];
    s_state[13] = __hwport_aes_isbox(s_state[9]);
    s_state[9] = __hwport_aes_isbox(s_state[5]);
    s_state[5] = __hwport_aes_isbox(s_state[1]);
    s_state[1] = __hwport_aes_isbox(s_temp);

    s_temp = s_state[2];
    s_state[2] = __hwport_aes_isbox(s_state[10]);
    s_state[10] = __hwport_aes_isbox(s_temp);
    s_temp = s_state[6];
    s_state[6] = __hwport_aes_isbox(s_state[14]);
    s_state[14] = __hwport_aes_isbox(s_temp);

    s_temp = s_state[3];
    s_state[3] = __hwport_aes_isbox(s_state[7]);
    s_state[7] = __hwport_aes_isbox(s_state[11]);
    s_state[11] = __hwport_aes_isbox(s_state[15]);
    s_state[15] = __hwport_aes_isbox(s_temp);
}

static void hwport_aes_isubbyte_ishiftrows_imixcols(uint8_t *s_state)
{
    uint8_t s_temp[ def_hwport_aes_block_size ];

    (void)memcpy((void *)(&s_temp[0]), (const void *)(&s_state[0]), (size_t)def_hwport_aes_block_size);

    s_state[0] = __hwport_aes_isbox(__hwport_aes_xtimee(s_temp[0]) ^ __hwport_aes_xtimeb(s_temp[1]) ^ __hwport_aes_xtimed(s_temp[2]) ^ __hwport_aes_xtime9(s_temp[3]));
    s_state[5] = __hwport_aes_isbox(__hwport_aes_xtime9(s_temp[0]) ^ __hwport_aes_xtimee(s_temp[1]) ^ __hwport_aes_xtimeb(s_temp[2]) ^ __hwport_aes_xtimed(s_temp[3]));
    s_state[10] = __hwport_aes_isbox(__hwport_aes_xtimed(s_temp[0]) ^ __hwport_aes_xtime9(s_temp[1]) ^ __hwport_aes_xtimee(s_temp[2]) ^ __hwport_aes_xtimeb(s_temp[3]));
    s_state[15] = __hwport_aes_isbox(__hwport_aes_xtimeb(s_temp[0]) ^ __hwport_aes_xtimed(s_temp[1]) ^ __hwport_aes_xtime9(s_temp[2]) ^ __hwport_aes_xtimee(s_temp[3]));

    s_state[4] = __hwport_aes_isbox(__hwport_aes_xtimee(s_temp[4]) ^ __hwport_aes_xtimeb(s_temp[5]) ^ __hwport_aes_xtimed(s_temp[6]) ^ __hwport_aes_xtime9(s_temp[7]));
    s_state[9] = __hwport_aes_isbox(__hwport_aes_xtime9(s_temp[4]) ^ __hwport_aes_xtimee(s_temp[5]) ^ __hwport_aes_xtimeb(s_temp[6]) ^ __hwport_aes_xtimed(s_temp[7]));
    s_state[14] = __hwport_aes_isbox(__hwport_aes_xtimed(s_temp[4]) ^ __hwport_aes_xtime9(s_temp[5]) ^ __hwport_aes_xtimee(s_temp[6]) ^ __hwport_aes_xtimeb(s_temp[7]));
    s_state[3] = __hwport_aes_isbox(__hwport_aes_xtimeb(s_temp[4]) ^ __hwport_aes_xtimed(s_temp[5]) ^ __hwport_aes_xtime9(s_temp[6]) ^ __hwport_aes_xtimee(s_temp[7]));

    s_state[8] = __hwport_aes_isbox(__hwport_aes_xtimee(s_temp[8]) ^ __hwport_aes_xtimeb(s_temp[9]) ^ __hwport_aes_xtimed(s_temp[10]) ^ __hwport_aes_xtime9(s_temp[11]));
    s_state[13] = __hwport_aes_isbox(__hwport_aes_xtime9(s_temp[8]) ^ __hwport_aes_xtimee(s_temp[9]) ^ __hwport_aes_xtimeb(s_temp[10]) ^ __hwport_aes_xtimed(s_temp[11]));
    s_state[2] = __hwport_aes_isbox(__hwport_aes_xtimed(s_temp[8]) ^ __hwport_aes_xtime9(s_temp[9]) ^ __hwport_aes_xtimee(s_temp[10]) ^ __hwport_aes_xtimeb(s_temp[11]));
    s_state[7] = __hwport_aes_isbox(__hwport_aes_xtimeb(s_temp[8]) ^ __hwport_aes_xtimed(s_temp[9]) ^ __hwport_aes_xtime9(s_temp[10]) ^ __hwport_aes_xtimee(s_temp[11]));

    s_state[12] = __hwport_aes_isbox(__hwport_aes_xtimee(s_temp[12]) ^ __hwport_aes_xtimeb(s_temp[13]) ^ __hwport_aes_xtimed(s_temp[14]) ^ __hwport_aes_xtime9(s_temp[15]));
    s_state[1] = __hwport_aes_isbox(__hwport_aes_xtime9(s_temp[12]) ^ __hwport_aes_xtimee(s_temp[13]) ^ __hwport_aes_xtimeb(s_temp[14]) ^ __hwport_aes_xtimed(s_temp[15]));
    s_state[6] = __hwport_aes_isbox(__hwport_aes_xtimed(s_temp[12]) ^ __hwport_aes_xtime9(s_temp[13]) ^ __hwport_aes_xtimee(s_temp[14]) ^ __hwport_aes_xtimeb(s_temp[15]));
    s_state[11] = __hwport_aes_isbox(__hwport_aes_xtimeb(s_temp[12]) ^ __hwport_aes_xtimed(s_temp[13]) ^ __hwport_aes_xtime9(s_temp[14]) ^ __hwport_aes_xtimee(s_temp[15]));
}

static void __hwport_aes_decrypt_block(size_t s_rounds, void *s_plain_text, const void *s_cipher_text, const void *s_round_key)
{
    uint8_t s_state[ def_hwport_aes_block_size ];

    size_t s_offset;

    hwport_aes_first_addroundkey((void *)(&s_state[0]), s_cipher_text, hwport_peek_const(s_round_key, s_rounds * ((size_t)def_hwport_aes_block_size)));
    hwport_aes_isubbytes_ishiftrows((uint8_t *)(&s_state[0]));

    for(s_offset = s_rounds - ((size_t)1u);s_offset > ((size_t)0u);--s_offset) { 
        hwport_aes_addroundkey((void *)(&s_state[0]), hwport_peek_const(s_round_key, s_offset * ((size_t)def_hwport_aes_block_size)));
        hwport_aes_isubbyte_ishiftrows_imixcols((uint8_t *)(&s_state[0]));
    }

    hwport_aes_last_addroundkey(s_plain_text, (const void *)(&s_state[0]), s_round_key);
}

static void hwport_aes128_decrypt_block(void *s_plain_text, const void *s_cipher_text, const void *s_round_key)
{
    __hwport_aes_decrypt_block(def_hwport_aes128_rounds, s_plain_text, s_cipher_text, s_round_key);
}

static void hwport_aes192_decrypt_block(void *s_plain_text, const void *s_cipher_text, const void *s_round_key)
{
    __hwport_aes_decrypt_block(def_hwport_aes192_rounds, s_plain_text, s_cipher_text, s_round_key);
}

static void hwport_aes256_decrypt_block(void *s_plain_text, const void *s_cipher_text, const void *s_round_key)
{
    __hwport_aes_decrypt_block(def_hwport_aes256_rounds, s_plain_text, s_cipher_text, s_round_key);
}

void *hwport_encrypt_aes128_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    size_t s_offset;

    s_offset = (size_t)0u;
    while((s_offset + ((size_t)def_hwport_aes_block_size)) <= s_size) {
        hwport_aes128_encrypt_block(hwport_peek(s_data, s_offset), hwport_peek_const(s_data, s_offset), s_round_key);
        s_offset += (size_t)def_hwport_aes_block_size;
    }

    return(s_data);
}

void *hwport_decrypt_aes128_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    size_t s_offset;

    s_offset = (size_t)0u;
    while((s_offset + ((size_t)def_hwport_aes_block_size)) <= s_size) {
        hwport_aes128_decrypt_block(hwport_peek(s_data, s_offset), hwport_peek_const(s_data, s_offset), s_round_key);
        s_offset += (size_t)def_hwport_aes_block_size;
    }

    return(s_data);
}

void *hwport_encrypt_aes128_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_cfb8(hwport_encrypt_aes128_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes128_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_cfb8(hwport_encrypt_aes128_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes128_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_ofb8(hwport_encrypt_aes128_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes128_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_ofb8(hwport_encrypt_aes128_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes128_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_cbc(hwport_encrypt_aes128_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes128_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_cbc(hwport_decrypt_aes128_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes192_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    size_t s_offset;

    s_offset = (size_t)0u;
    while((s_offset + ((size_t)def_hwport_aes_block_size)) <= s_size) {
        hwport_aes192_encrypt_block(hwport_peek(s_data, s_offset), hwport_peek_const(s_data, s_offset), s_round_key);
        s_offset += (size_t)def_hwport_aes_block_size;
    }

    return(s_data);
}

void *hwport_decrypt_aes192_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    size_t s_offset;

    s_offset = (size_t)0u;
    while((s_offset + ((size_t)def_hwport_aes_block_size)) <= s_size) {
        hwport_aes192_decrypt_block(hwport_peek(s_data, s_offset), hwport_peek_const(s_data, s_offset), s_round_key);
        s_offset += (size_t)def_hwport_aes_block_size;
    }

    return(s_data);
}

void *hwport_encrypt_aes192_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_cfb8(hwport_encrypt_aes192_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes192_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_cfb8(hwport_encrypt_aes192_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes192_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_ofb8(hwport_encrypt_aes192_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes192_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_ofb8(hwport_encrypt_aes192_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes192_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_cbc(hwport_encrypt_aes192_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes192_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_cbc(hwport_decrypt_aes192_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes256_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    size_t s_offset;

    s_offset = (size_t)0u;
    while((s_offset + ((size_t)def_hwport_aes_block_size)) <= s_size) {
        hwport_aes256_encrypt_block(hwport_peek(s_data, s_offset), hwport_peek_const(s_data, s_offset), s_round_key);
        s_offset += (size_t)def_hwport_aes_block_size;
    }

    return(s_data);
}

void *hwport_decrypt_aes256_ecb(void *s_data, size_t s_size, const void *s_round_key)
{
    size_t s_offset;

    s_offset = (size_t)0u;
    while((s_offset + ((size_t)def_hwport_aes_block_size)) <= s_size) {
        hwport_aes256_decrypt_block(hwport_peek(s_data, s_offset), hwport_peek_const(s_data, s_offset), s_round_key);
        s_offset += (size_t)def_hwport_aes_block_size;
    }

    return(s_data);
}

void *hwport_encrypt_aes256_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_cfb8(hwport_encrypt_aes256_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes256_cfb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_cfb8(hwport_encrypt_aes256_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes256_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_ofb8(hwport_encrypt_aes256_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes256_ofb8(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_ofb8(hwport_encrypt_aes256_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_encrypt_aes256_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_encrypt_mode_cbc(hwport_encrypt_aes256_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

void *hwport_decrypt_aes256_cbc(void *s_data, size_t s_size, void *s_initial_vector, const void *s_round_key)
{
    return(hwport_decrypt_mode_cbc(hwport_decrypt_aes256_ecb, def_hwport_aes_block_size, s_data, s_size, s_initial_vector, s_round_key));
}

#endif

/* vim:set noexpandtab tabstop=4 shiftwidth=4 softtabstop=4 autoindent cindent smarttab fileencoding=utf8: */
/* End of source */
