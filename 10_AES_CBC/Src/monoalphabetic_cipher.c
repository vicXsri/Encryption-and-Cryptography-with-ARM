/*
 * monoalphabetic_cipher.c
 *
 *  Created on: Feb 12, 2026
 *      @author: Srivisweswara Mohan Santhi
 */


#include "monoalphabetic_cipher.h"


void monoalphabetic_cipher_encrypt(uint8_t* plainText, uint8_t* key, uint8_t* encryptedText){

	for(int i =0; i <= sizeof(plainText); i++){
		if 		(isupper(plainText[i])) encryptedText[i] = key[plainText[i] - 65];
		else if (islower(plainText[i])) encryptedText[i] = key[plainText[i] - 97];
		else 	encryptedText[i] = plainText[i];
	}

}

void monoalphabetic_cipher_decrypt(uint8_t* encryptedText, uint8_t* key, uint8_t* decryptedText){

	for(int i =0; i <= sizeof(encryptedText); i++){

		if (isupper(encryptedText[i])){
			for(int j=0; j < 26; j++){
				if(key[j] == encryptedText[i]) decryptedText[i] = j + 65;
			}
		}

		else if (islower(encryptedText[i])){
			for(int j=0; j < 26; j++){
				if(key[j] == encryptedText[i]) decryptedText[i] = j + 97;
			}
		}

		else{
			decryptedText[i] = encryptedText[i];
		}

	}
}
