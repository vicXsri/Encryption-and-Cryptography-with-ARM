#include "main.h"


/*Module:
 * FPU
 * UART
 * GPIO (BSP)
 * TIMEBASE
uint8_t key = 3;
uint8_t length = 5;
 */

#define text_len	6

uint8_t encryptedText[text_len];
uint8_t decryptedText[text_len];
uint8_t plainText[] = "HELLO";
uint8_t key[] ="KEY";


int main(){
	fpu_enable();
	debug_uart_init();
	timebase_init();

	printf("Vigenere alphabetic Cipher\r\n\n");

	printf("Vigenere alphabetic Cipher Plain Text: %s \r\n", plainText);
	printf("Vigenere alphabetic Cipher Key: %s \r\n\n", key);

	printf("Vigenere alphabetic Cipher Encryption\r\n\n");
	vigenerealphabetic_cipher_encrypt(plainText,key,encryptedText);
	printf("Vigenere alphabetic Cipher Encrypted Data : %s\r\n\n",encryptedText);

	printf("Vigenere alphabetic Cipher Decryption\r\n\n");
	vigenerealphabetic_cipher_decrypt(encryptedText,key,decryptedText);
	printf("Vigenere alphabetic Cipher Decrypted Data : %s\r\n\n",decryptedText);

	while(1){}
}

























//	printf("Caesar Cipher\r\n\n");
//
//	printf("Caesar Cipher Plain Text: %s \r\n\n", plainText);
//
//	printf("Caesar Cipher Encryption\r\n\n");
//	caesar_cipher_encrypt(plainText,key,encryptedText,length);
//	printf("Caesar Cipher Encrypted Data : %s\r\n\n",encryptedText);
//
//	printf("Caesar Cipher Decryption\r\n\n");
//	caesar_cipher_decrypt(encryptedText,key,decryptedText,length);
//	printf("Caesar Cipher Decrypted Data : %s\r\n\n",decryptedText);












//button_init();
//	led_init();
//	pa1_adc_init();
//		delay(1);
//		get_btn_state() ? led_on() : led_off();
