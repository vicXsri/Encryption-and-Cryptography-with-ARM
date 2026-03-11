/*
 * monoalphabetic_cipher.c
 *
 *  Created on: Feb 12, 2026
 *      @author: Srivisweswara Mohan Santhi
 */


#include "vigenere_cipher.h"


void vigenerealphabetic_cipher_encrypt(uint8_t* plainText, uint8_t* key, uint8_t* encryptedText){

	int keyLen = sizeof(key), j=0;

	for(int i=0;plainText[i] != '\0'; i++){
		if(j == (keyLen-1)) j=0;
		if(isupper(plainText[i])) encryptedText[i] = (((plainText[i] - 65) + (key[j++] - 65)) % 26) + 65;
		else encryptedText[i] = (((plainText[i] - 97) + (key[j++] - 97)) % 26) + 97;
	}
}

void vigenerealphabetic_cipher_decrypt(uint8_t* encryptedText, uint8_t* key, uint8_t* decryptedText){

	int keyLen = sizeof(key), j=0;

	for(int i=0;encryptedText[i] != '\0'; i++){
		if(j == (keyLen-1)) j=0;
		if(isupper(encryptedText[i])) decryptedText[i] = (((encryptedText[i] - 65) - (key[j++] - 65) + 26) % 26) + 65;
		else decryptedText[i] = (( (encryptedText[i] - 97) - (key[j++]- 97) + 26) % 26) + 97;
	}
}
