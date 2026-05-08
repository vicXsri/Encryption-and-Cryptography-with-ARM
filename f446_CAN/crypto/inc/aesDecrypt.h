/*
 * aesEncrypt.h
 *
 *  Created on: Mar 4, 2026
 *      @author: Srivisweswara Mohan Santhi
 */

#ifndef AESDECRYPT_H_
#define AESDECRYPT_H_



#include "main.h"



status InvSubBytes(const uint8_t (*arr)[4]);
status InvShiftRows(const uint8_t (*arr)[4]);
status InvAddRoundKey(const uint8_t (*arr)[4], const uint8_t (*key)[4]);

status decrypt(uint8_t (*arr)[4], uint8_t round, uint8_t round_key[][4][4]);


status AES128_Decrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen);
status AES192_Decrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen);
status AES256_Decrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen);

#endif
