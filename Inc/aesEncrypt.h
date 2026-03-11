/*
 * aesEncrypt.h
 *
 *  Created on: Mar 4, 2026
 *      @author: Srivisweswara Mohan Santhi
 */

#ifndef AESENCRYPT_H_
#define AESENCRYPT_H_

#include "main.h"

status SubBytes(const uint8_t (*arr)[4]);
status ShiftRows(const uint8_t (*arr)[4]);
status MixColumns(const uint8_t (*arr)[4]);
status AddRoundKey(const uint8_t (*arr)[4], const uint8_t (*key)[4]);


status AES128_Encrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen);
status AES192_Encrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen);
status AES256_Encrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen);


status encrypt(uint8_t (*arr)[4], uint8_t round, uint8_t round_key[][4][4]);

#endif /* AESENCRYPT_H_ */
