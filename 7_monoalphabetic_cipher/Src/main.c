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
uint8_t key1[] ="UNOWYHGIRBLJZAKVTDMQSCPFXE";


int main(){
	fpu_enable();
	debug_uart_init();
	timebase_init();

	printf("Monoalphabetic Cipher\r\n\n");

	printf("Monoalphabetic Cipher Plain Text: %s \r\n\n", plainText);

	printf("Monoalphabetic Cipher Encryption\r\n\n");
	monoalphabetic_cipher_encrypt(plainText,key1,encryptedText);
	printf("Monoalphabetic Cipher Encrypted Data : %s\r\n\n",encryptedText);

	printf("Monoalphabetic Cipher Decryption\r\n\n");
	monoalphabetic_cipher_decrypt(encryptedText,key1,decryptedText);
	printf("Monoalphabetic Cipher Decrypted Data : %s\r\n\n",decryptedText);

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
