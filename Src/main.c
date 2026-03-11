#include "main.h"


/*Module:
 * FPU
 * UART
 * GPIO (BSP)
 * TIMEBASE
uint8_t key = 3;
uint8_t length = 5;
 */

/** Extract from NIST Special Publication 800-38A
  * F.2.1 CBC-AES128.Encrypt
    Key 2b7e151628aed2a6abf7158809cf4f3c
    IV 000102030405060708090a0b0c0d0e0f

    Block #1
    Plaintext 6bc1bee22e409f96e93d7e117393172a
    Input Block 6bc0bce12a459991e134741a7f9e1925
    Output Block 7649abac8119b246cee98e9b12e9197d
    Ciphertext 7649abac8119b246cee98e9b12e9197d

    Block #2
    Plaintext ae2d8a571e03ac9c9eb76fac45af8e51
    Input Block d86421fb9f1a1eda505ee1375746972c
    Output Block 5086cb9b507219ee95db113a917678b2
    Ciphertext 5086cb9b507219ee95db113a917678b2

    Block #3
    Plaintext 30c81c46a35ce411e5fbc1191a0a52ef
    Input Block 604ed7ddf32efdff7020d0238b7c2a5d
    Output Block 73bed6b8e3c1743b7116e69e22229516
    Ciphertext 73bed6b8e3c1743b7116e69e22229516

    Block #4
    Plaintext f69f2445df4f9b17ad2b417be66c3710
    Input Block 8521f2fd3c8eef2cdc3da7e5c44ea206
    Output Block 3ff1caa1681fac09120eca307586e1a7
    Ciphertext 3ff1caa1681fac09120eca307586e1a7
  */

/*************************************************************************/

uint8_t fulltext[] =
{
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c,
};
/*************************************************************************/

uint8_t key128_1[16]  = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};

/*************************************************************************/

uint8_t key192_1[24] = {
    0x8E, 0x73, 0xB0, 0xF7,
    0xDA, 0x0E, 0x64, 0x52,
    0xC8, 0x10, 0xF3, 0x2B,
    0x80, 0x90, 0x79, 0xE5,
    0x62, 0xF8, 0xEA, 0xD2,
    0x52, 0x2C, 0x6B, 0x7B
};

/*************************************************************************/

uint8_t key256_1[32] = {
    0x60, 0x3D, 0xEB, 0x10,
    0x15, 0xCA, 0x71, 0xBE,
    0x2B, 0x73, 0xAE, 0xF0,
    0x85, 0x7D, 0x77, 0x81,
    0x1F, 0x35, 0x2C, 0x07,
    0x3B, 0x61, 0x08, 0xD7,
    0x2D, 0x98, 0x10, 0xA3,
    0x09, 0x14, 0xDF, 0xF4
};

/*************************************************************************/
uint8_t IV[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
/*************************************************************************/
uint8_t Init_Counter[] =
{
 0xf0, 0xf1, 0xf2,0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};
/*************************************************************************/

uint8_t EncryptData128[64]={0};
uint8_t EncryptData192[64]={0};
uint8_t EncryptData256[64]={0};

size_t EncryptData128Size=0;
size_t EncryptData192Size=0;
size_t EncryptData256Size=0;

uint8_t DecryptData128[180]={0};
uint8_t DecryptData192[180]={0};
uint8_t DecryptData256[180]={0};

size_t DecryptData128Size=0;
size_t DecryptData192Size=0;
size_t DecryptData256Size=0;

void AES128_ECB();
void AES192_ECB();
void AES256_ECB();

void AES128_CBC();
void AES192_CBC();
void AES256_CBC();

void AES128_CFB();
void AES192_CFB();
void AES256_CFB();

void AES128_OFB();
void AES192_OFB();
void AES256_OFB();

void AES128_CTR();
void AES192_CTR();
void AES256_CTR();

void outputprint(size_t length, uint8_t *data);

int main(){

	fpu_enable();

	debug_uart_init();
	timebase_init();


//     AES128_ECB();
//     AES192_ECB();
//     AES256_ECB();

//     AES128_CBC();
//     AES192_CBC();
//     AES256_CBC();

//	 AES128_CFB();
//	 AES192_CFB();
//     AES256_CFB();

//	 AES128_OFB();
//	 AES192_OFB();
//     AES256_OFB();

//	 AES128_CTR();
//	 AES192_CTR();
//     AES256_CTR();

	while(1){}
}


void AES128_ECB(){
    /*AES128*/

    if(AES128_Encrypt(AES_ECB_ENC, fulltext, sizeof(fulltext), key128_1, IV, EncryptData128, &EncryptData128Size) != success)    printf("\nAES128 ECB Cipher Encrypt Failed\n");
    else    printf("\nAES128 ECB Cipher Encrypt Success\n");

    if(AES128_Decrypt(AES_ECB_DEC, EncryptData128, sizeof(EncryptData128), key128_1, IV, DecryptData128, &DecryptData128Size) != success)    printf("\nAES128 ECB Cipher Decrypt Failed\n");
    else    printf("\nAES128 ECB Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData128Size, EncryptData128);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData128Size, DecryptData128);

    printf("\nEncrypt size -> %d\r\n\r\n", EncryptData128Size);
    printf("\nDecrypt size -> %d\r\n\r\n", DecryptData128Size);
}

void AES192_ECB(){
    /*AES192*/

    if(AES192_Encrypt(AES_ECB_ENC, fulltext, sizeof(fulltext), key192_1, IV, EncryptData192, &EncryptData192Size) != success)    printf("\nAES192 ECB Cipher Encrypt Failed\n");
    else    printf("\r\nAES192 ECB Cipher Encrypt Success\r\n");

    if(AES192_Decrypt(AES_ECB_DEC, EncryptData192, sizeof(EncryptData192), key192_1, IV, DecryptData192, &DecryptData192Size) != success)    printf("\nAES192 ECB Cipher Decrypt Failed\n");
    else    printf("\nAES192 ECB Cipher Decrypt Success\r\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData192Size, EncryptData192);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData192Size, DecryptData192);

    printf("\nEncrypt size -> %d\r\n", EncryptData192Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData192Size);
}

void AES256_ECB(){
    /*AES256*/

    if(AES256_Encrypt(AES_ECB_ENC, fulltext, sizeof(fulltext), key256_1, IV, EncryptData256, &EncryptData256Size) != success)    printf("\nAES256 ECB Cipher Encrypt Failed\n");
    else    printf("\nAES256 ECB Cipher Encrypt Success\n");

    if(AES256_Decrypt(AES_ECB_DEC, EncryptData256, sizeof(EncryptData256), key256_1, IV, DecryptData256, &DecryptData256Size) != success)    printf("\nAES256 ECB Cipher Decrypt Failed\n");
    else    printf("\nAES256 ECB CCBC ipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData256Size, EncryptData256);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData256Size, DecryptData256);

    printf("\nEncrypt Size -> %d\r\n", EncryptData256Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData256Size);

}

void AES128_CBC(){
    /*AES128*/

    if(AES128_Encrypt(AES_CBC_ENC, fulltext, sizeof(fulltext), key128_1, IV, EncryptData128, &EncryptData128Size) != success)    printf("\nAES128 CBC Cipher Encrypt Failed\n");
    else    printf("\nAES128 CBC Cipher Encrypt Success\n");

    if(AES128_Decrypt(AES_CBC_DEC, EncryptData128, sizeof(EncryptData128), key128_1, IV, DecryptData128, &DecryptData128Size) != success)    printf("\nAES128 CBC Cipher Decrypt Failed\n");
    else    printf("\nAES128 CBC Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData128Size, EncryptData128);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData128Size, DecryptData128);

    printf("\nEncrypt size -> %d\r\n\r\n", EncryptData128Size);
    printf("\nDecrypt size -> %d\r\n\r\n", DecryptData128Size);
}

void AES192_CBC(){
    /*AES192*/

    if(AES192_Encrypt(AES_CBC_ENC, fulltext, sizeof(fulltext), key192_1, IV, EncryptData192, &EncryptData192Size) != success)    printf("\nAES192 CBC Cipher Encrypt Failed\n");
    else    printf("\r\nAES192 CBC Cipher Encrypt Success\r\n");

    if(AES192_Decrypt(AES_CBC_DEC, EncryptData192, sizeof(EncryptData192), key192_1, IV, DecryptData192, &DecryptData192Size) != success)    printf("\nAES192 CBC Cipher Decrypt Failed\n");
    else    printf("\nAES192 CBC Cipher Decrypt Success\r\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData192Size, EncryptData192);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData192Size, DecryptData192);

    printf("\nEncrypt size -> %d\r\n", EncryptData192Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData192Size);
}

void AES256_CBC(){
    /*AES256*/

    if(AES256_Encrypt(AES_CBC_ENC, fulltext, sizeof(fulltext), key256_1, IV, EncryptData256, &EncryptData256Size) != success)    printf("\nAES256 CBC Cipher Encrypt Failed\n");
    else    printf("\nAES256 CBC Cipher Encrypt Success\n");

    if(AES256_Decrypt(AES_CBC_DEC, EncryptData256, sizeof(EncryptData256), key256_1, IV, DecryptData256, &DecryptData256Size) != success)    printf("\nAES256 CBC Cipher Decrypt Failed\n");
    else    printf("\nAES256 CBC Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData256Size, EncryptData256);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData256Size, DecryptData256);

    printf("\nEncrypt Size -> %d\r\n", EncryptData256Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData256Size);

}

void AES128_CFB(){
    /*AES128*/

    if(AES128_Encrypt(AES_CFB_ENC, fulltext, sizeof(fulltext), key128_1, IV, EncryptData128, &EncryptData128Size) != success)    printf("\nAES128 CFB Cipher Encrypt Failed\n");
    else    printf("\nAES128 CFB Cipher Encrypt Success\n");

    if(AES128_Decrypt(AES_CFB_DEC, EncryptData128, sizeof(EncryptData128), key128_1, IV, DecryptData128, &DecryptData128Size) != success)    printf("\nAES128 CFB Cipher Decrypt Failed\n");
    else    printf("\nAES128 CFB Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData128Size, EncryptData128);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData128Size, DecryptData128);

    printf("\nEncrypt size -> %d\r\n\r\n", EncryptData128Size);
    printf("\nDecrypt size -> %d\r\n\r\n", DecryptData128Size);
}

void AES192_CFB(){
    /*AES192*/

    if(AES192_Encrypt(AES_CFB_ENC, fulltext, sizeof(fulltext), key192_1, IV, EncryptData192, &EncryptData192Size) != success)    printf("\nAES192 CFB Cipher Encrypt Failed\n");
    else    printf("\r\nAES192 CFB Cipher Encrypt Success\r\n");

    if(AES192_Decrypt(AES_CFB_DEC, EncryptData192, sizeof(EncryptData192), key192_1, IV, DecryptData192, &DecryptData192Size) != success)    printf("\nAES192 CFB Cipher Decrypt Failed\n");
    else    printf("\nAES192 CFB Cipher Decrypt Success\r\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData192Size, EncryptData192);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData192Size, DecryptData192);

    printf("\nEncrypt size -> %d\r\n", EncryptData192Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData192Size);
}

void AES256_CFB(){
    /*AES256*/

    if(AES256_Encrypt(AES_CFB_ENC, fulltext, sizeof(fulltext), key256_1, IV, EncryptData256, &EncryptData256Size) != success)    printf("\nAES256 CFB Cipher Encrypt Failed\n");
    else    printf("\nAES256 CFB Cipher Encrypt Success\n");

    if(AES256_Decrypt(AES_CFB_DEC, EncryptData256, sizeof(EncryptData256), key256_1, IV, DecryptData256, &DecryptData256Size) != success)    printf("\nAES256 CFB Cipher Decrypt Failed\n");
    else    printf("\nAES256 CFB Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData256Size, EncryptData256);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData256Size, DecryptData256);

    printf("\nEncrypt Size -> %d\r\n", EncryptData256Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData256Size);

}

void AES128_OFB(){
    /*AES128*/

    if(AES128_Encrypt(AES_OFB_ENC, fulltext, sizeof(fulltext), key128_1, IV, EncryptData128, &EncryptData128Size) != success)    printf("\nAES128 OFB Cipher Encrypt Failed\n");
    else    printf("\nAES128 OFB Cipher Encrypt Success\n");

    if(AES128_Decrypt(AES_OFB_DEC, EncryptData128, sizeof(EncryptData128), key128_1, IV, DecryptData128, &DecryptData128Size) != success)    printf("\nAES128 OFB Cipher Decrypt Failed\n");
    else    printf("\nAES128 OFB Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData128Size, EncryptData128);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData128Size, DecryptData128);

    printf("\nEncrypt size -> %d\r\n\r\n", EncryptData128Size);
    printf("\nDecrypt size -> %d\r\n\r\n", DecryptData128Size);
}

void AES192_OFB(){
    /*AES192*/

    if(AES192_Encrypt(AES_OFB_ENC, fulltext, sizeof(fulltext), key192_1, IV, EncryptData192, &EncryptData192Size) != success)    printf("\nAES192 OFB Cipher Encrypt Failed\n");
    else    printf("\r\nAES192 OFB Cipher Encrypt Success\r\n");

    if(AES192_Decrypt(AES_OFB_DEC, EncryptData192, sizeof(EncryptData192), key192_1, IV, DecryptData192, &DecryptData192Size) != success)    printf("\nAES192 OFB Cipher Decrypt Failed\n");
    else    printf("\nAES192 OFB Cipher Decrypt Success\r\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData192Size, EncryptData192);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData192Size, DecryptData192);

    printf("\nEncrypt size -> %d\r\n", EncryptData192Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData192Size);
}

void AES256_OFB(){
    /*AES256*/

    if(AES256_Encrypt(AES_OFB_ENC, fulltext, sizeof(fulltext), key256_1, IV, EncryptData256, &EncryptData256Size) != success)    printf("\nAES256 OFB Cipher Encrypt Failed\n");
    else    printf("\nAES256 OFB Cipher Encrypt Success\n");

    if(AES256_Decrypt(AES_OFB_DEC, EncryptData256, sizeof(EncryptData256), key256_1, IV, DecryptData256, &DecryptData256Size) != success)    printf("\nAES256 OFB Cipher Decrypt Failed\n");
    else    printf("\nAES256 OFB Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData256Size, EncryptData256);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData256Size, DecryptData256);

    printf("\nEncrypt Size -> %d\r\n", EncryptData256Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData256Size);

}

void AES128_CTR(){
    /*AES128*/

    if(AES128_Encrypt(AES_CTR_ENC, fulltext, sizeof(fulltext), key128_1, Init_Counter, EncryptData128, &EncryptData128Size) != success)    printf("\nAES128 CTR Cipher Encrypt Failed\n");
    else    printf("\nAES128 CTR Cipher Encrypt Success\n");

    if(AES128_Decrypt(AES_CTR_DEC, EncryptData128, sizeof(EncryptData128), key128_1, Init_Counter, DecryptData128, &DecryptData128Size) != success)    printf("\nAES128 CTR Cipher Decrypt Failed\n");
    else    printf("\nAES128 CTR Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData128Size, EncryptData128);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData128Size, DecryptData128);

    printf("\nEncrypt size -> %d\r\n\r\n", EncryptData128Size);
    printf("\nDecrypt size -> %d\r\n\r\n", DecryptData128Size);
}

void AES192_CTR(){
    /*AES192*/

    if(AES192_Encrypt(AES_CTR_ENC, fulltext, sizeof(fulltext), key192_1, Init_Counter, EncryptData192, &EncryptData192Size) != success)    printf("\nAES192 CTR Cipher Encrypt Failed\n");
    else    printf("\r\nAES192 CTR Cipher Encrypt Success\r\n");

    if(AES192_Decrypt(AES_CTR_DEC, EncryptData192, sizeof(EncryptData192), key192_1, Init_Counter, DecryptData192, &DecryptData192Size) != success)    printf("\nAES192 CTR Cipher Decrypt Failed\n");
    else    printf("\nAES192 CTR Cipher Decrypt Success\r\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData192Size, EncryptData192);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData192Size, DecryptData192);

    printf("\nEncrypt size -> %d\r\n", EncryptData192Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData192Size);
}

void AES256_CTR(){
    /*AES256*/

    if(AES256_Encrypt(AES_CTR_ENC, fulltext, sizeof(fulltext), key256_1, Init_Counter, EncryptData256, &EncryptData256Size) != success)    printf("\nAES256 CTR Cipher Encrypt Failed\n");
    else    printf("\nAES256 CTR Cipher Encrypt Success\n");

    if(AES256_Decrypt(AES_CTR_DEC, EncryptData256, sizeof(EncryptData256), key256_1, Init_Counter, DecryptData256, &DecryptData256Size) != success)    printf("\nAES256 CTR Cipher Decrypt Failed\n");
    else    printf("\nAES256 CTR Cipher Decrypt Success\n");

    printf("\r\nEncrypted Data\r\n\r\n");
    outputprint(EncryptData256Size, EncryptData256);

    printf("\r\nDecrypted Data\r\n\r\n");
    outputprint(DecryptData256Size, DecryptData256);

    printf("\nEncrypt Size -> %d\r\n", EncryptData256Size);
    printf("\nDecrypt size -> %d\r\n", DecryptData256Size);

}

void outputprint(size_t length, uint8_t *data) {
    printf("\r\n");

    for (int i = 0; i < length; i++) {

        if (i % 16 == 0) printf("\r\n");

        if (i % 4 == 0) printf(" ");

        printf("0x%02X ", data[i]);
    }

    printf("\r\n");
}
