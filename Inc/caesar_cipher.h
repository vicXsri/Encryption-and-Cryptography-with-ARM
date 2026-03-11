/*
 * ceaser_cipher.h
 *
 *  Created on: Feb 12, 2026
 *      Author: Vichu
 */

#ifndef CAESAR_CIPHER_H_
#define CAESAR_CIPHER_H_

#include "main.h"

void caesar_cipher_encrypt(uint8_t* plainText, uint8_t key, uint8_t* encryptedText, uint32_t length);
void caesar_cipher_decrypt(uint8_t* encryptedText, uint8_t key, uint8_t* decryptedText, uint32_t length);

#endif /* CAESAR_CIPHER_H_ */
