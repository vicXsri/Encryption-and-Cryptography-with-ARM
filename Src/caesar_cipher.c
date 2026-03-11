/*
 * ceaser_cipher.c
 *
 *  Created on: Feb 12, 2026
 *      Author: Vichu
 */
#include "caesar_cipher.h"

void caesar_cipher_encrypt(uint8_t* plainText, uint8_t key, uint8_t* encryptedText, uint32_t length){

	for(uint32_t i=0; i < length; i++){
		if(isupper(plainText[i]))	encryptedText[i] = ((plainText[i] - 65 + key) % 26) + 65;
		else	encryptedText[i] = ((plainText[i] - 97 + key) % 26) + 97;
 	}

	encryptedText[length] = '\0';

}

void caesar_cipher_decrypt(uint8_t* encryptedText, uint8_t key, uint8_t* decryptedText, uint32_t length){

	for(uint32_t i=0; i < length; i++){
		if(isupper(encryptedText[i])) decryptedText[i] = (((encryptedText[i] - 65) - key) % 26) + 65;
		else	decryptedText[i] = (((encryptedText[i] - 97) - key) % 26) + 97;
 	}

	decryptedText[length] = '\0';

}
