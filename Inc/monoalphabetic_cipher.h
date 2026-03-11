/*
 * monoalphabetic_cipher.h
 *
 *  Created on: Feb 12, 2026
 *      @author: Srivisweswara Mohan Santhi
 */

#ifndef MONOALPHABETIC_CIPHER_H_
#define MONOALPHABETIC_CIPHER_H_

#include "main.h"


void monoalphabetic_cipher_encrypt(uint8_t* plainText, uint8_t* key, uint8_t* encryptedText);
void monoalphabetic_cipher_decrypt(uint8_t* encryptedText, uint8_t* key, uint8_t* decryptedText);

#endif /* MONOALPHABETIC_CIPHER_H_ */
