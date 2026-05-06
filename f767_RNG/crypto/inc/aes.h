#ifndef AES_H_
#define AES_H_

#include "main.h"



#define AES_ECB_ENC 0x00
#define AES_ECB_DEC 0x01

#define AES_CBC_ENC 0x02
#define AES_CBC_DEC 0x03

#define AES_CFB_ENC 0x04
#define AES_CFB_DEC 0x05

#define AES_OFB_ENC 0x06
#define AES_OFB_DEC 0x07

#define AES_CTR_ENC 0x08
#define AES_CTR_DEC 0x09

uint8_t (*dim4(uint8_t *tex))[4];
uint8_t (*dim6(uint8_t *tex))[6];
uint8_t (*dim8(uint8_t *tex))[8];

int gf(int a, int b);

status keyExpansion128(uint8_t (*key)[4]);
status keyExpansion192(uint8_t key[4][6]);
status keyExpansion256(uint8_t key[4][8]);

#endif /* STATUS_H_ */
