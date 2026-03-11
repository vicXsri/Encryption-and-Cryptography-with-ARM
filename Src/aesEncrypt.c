/*
 * aesEncrypt.c
 *
 *  Created on: Mar 4, 2026
 *      @author: Srivisweswara Mohan Santhi
 */


#include "aesEncrypt.h"

uint8_t s_box[16][16] = {{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
                        {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
                        {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
                        {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
                        {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
                        {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
                        {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
                        {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
                        {0xCD, 0x0C, 0x13, 0xec, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
                        {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
                        {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
                        {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
                        {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
                        {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
                        {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
                        {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16}};

uint8_t predef[4][4] = {{0x02, 0x03, 0x01, 0x01},
                        {0x01, 0x02, 0x03, 0x01},
                        {0x01, 0x01, 0x02, 0x03},
                        {0x03, 0x01, 0x01, 0x02}};

uint8_t state[4][4] = {0x00};

extern uint8_t round_key128[11][4][4];
extern uint8_t round_key192[13][4][4];
extern uint8_t round_key256[15][4][4];

/* Substitution Bytes | Forward Substitution Bytes */
status SubBytes(const uint8_t (*arr)[4]){
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            state[i][j] = s_box[((arr[i][j] >> 4) & 0x0F)][(arr[i][j] & 0x0F)];

    return success;
}

status ShiftRows(const uint8_t (*arr)[4]){

    uint8_t temp = arr[1][0];
    state[1][0]  = arr[1][1];
    state[1][1]  = arr[1][2];
    state[1][2]  = arr[1][3];
    state[1][3]  = temp;

    uint8_t temp0 = arr[2][0];
    uint8_t temp1 = arr[2][1];
    state[2][0]   = arr[2][2];
    state[2][1]   = arr[2][3];
    state[2][2]   = temp0;
    state[2][3]   = temp1;

    temp        = arr[3][3];
    state[3][3] = arr[3][2];
    state[3][2] = arr[3][1];
    state[3][1] = arr[3][0];
    state[3][0] = temp;

    return success;
}

status MixColumns(const uint8_t (*arr)[4])
{
    uint8_t col[4];

    for (int c = 0; c < 4; c++)
    {
        col[0] = state[0][c];
        col[1] = state[1][c];
        col[2] = state[2][c];
        col[3] = state[3][c];

        state[0][c] =
              gf(0x02, col[0])
            ^ gf(0x03, col[1])
            ^ col[2]
            ^ col[3];

        state[1][c] =
              col[0]
            ^ gf(0x02, col[1])
            ^ gf(0x03, col[2])
            ^ col[3];

        state[2][c] =
              col[0]
            ^ col[1]
            ^ gf(0x02, col[2])
            ^ gf(0x03, col[3]);

        state[3][c] =
              gf(0x03, col[0])
            ^ col[1]
            ^ col[2]
            ^ gf(0x02, col[3]);
    }

    return success;
}

status AddRoundKey(const uint8_t (*arr)[4], const uint8_t (*key)[4]){
     for(int i=0; i<4; i++){
        for(int j=0; j<4; j++){
            state[i][j] = arr[i][j] ^ key[i][j];
        }
    }
    return success;
}

status encrypt(uint8_t (*arr)[4], uint8_t round, uint8_t round_key[][4][4]){
    printf("preaddRoundKey\r\n");
    (AddRoundKey(arr, round_key[0]) != success)?            printf("AddRoundKey Failed\r\n"):
                                                            printf("AddRoundKey Success\r\n");

    for(int i=1; i<=(round-1); i++){
        printf("Round - %d\r\n", i);
        (SubBytes(state) != success)?                       printf("SubBytes Failed\r\n"):
                                                            printf("SubBytes Success\r\n");
        (ShiftRows(state) != success)?                      printf("ShiftRows Failed\r\n"):
                                                            printf("ShiftRows Success\r\n");
        (MixColumns(state) != success)?                     printf("MixColumns Failed\r\n"):
                                                            printf("MixColumns Success\r\n");
        (AddRoundKey(state, round_key[i]) != success)?      printf("AddRoundKey Failed\r\n"):
                                                            printf("AddRoundKey Success\r\n");
    }
    printf("Round - %d\r\n", round);
    (SubBytes(state) != success)?                           printf("SubBytes Failed\r\n"):
                                                            printf("SubBytes Success\r\n");
    (ShiftRows(state) != success)?                          printf("ShiftRows Failed\r\n"):
                                                            printf("ShiftRows Success\r\n");
    (AddRoundKey(state, round_key[round]) != success)?      printf("AddRoundKey Failed\r\n"):
                                                            printf("AddRoundKey Success\r\n");

    return success;
}

status AES128_ECB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize];

/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){

            for(int k=0; k < 16; k++)	bre[k] = temp[itr++];

            encrypt(dim4(bre), 10, round_key128);

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];
        }

        *encryptDataLen = eitr;

    return success;

}

status AES192_ECB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize];

/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){
            for(int k=0; k < 16; k++){
                bre[k] = temp[itr++];
            }
            encrypt(dim4(bre), 12, round_key192);
            for(uint8_t r=0; r<4;r++)
                for(uint8_t c=0; c<4;c++)
                    encryptData[eitr++] = state[c][r];
        }
        *encryptDataLen = eitr;

    return success;
}

status AES256_ECB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize];

/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/

        for(int i=0; i < newarr; i++){
            for(int k=0; k < 16; k++){
                bre[k] = temp[itr++];
            }
            encrypt(dim4(bre), 14, round_key256);
            for(uint8_t r=0; r<4;r++)
                for(uint8_t c=0; c<4;c++)
                    encryptData[eitr++] = state[c][r];
        }
        *encryptDataLen = eitr;

    return success;
}

status AES128_CBC_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, cbcitr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize];

/*********************************************************PKCS#7***************************************************************************/

    	for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));

/********************************************************************************************************************************************/

        for(int i =0 ;  i<16;i++)   temp[i] ^=  IV[i];

        for(int i=0; i< newarr; i++){
            for(int k=0; k < 16; k++)	bre[k] = temp[itr++];

            encrypt(dim4(bre), 10, round_key128);

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];

            for(int i =0 ;  i<16;i++)   temp[i+itr] ^= encryptData[cbcitr++];
        }
        *encryptDataLen = eitr;

    return success;

}

status AES192_CBC_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, cbcitr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize];

/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/
        for(int i =0 ;  i<16;i++)   temp[i] ^=  IV[i];

        for(int i=0; i< newarr; i++){
            for(int k=0; k < 16; k++){
                bre[k] = temp[itr++];
            }
            encrypt(dim4(bre), 12, round_key192);
            for(uint8_t r=0; r<4;r++)
                for(uint8_t c=0; c<4;c++)
                    encryptData[eitr++] = state[c][r];

            for(int i =0 ;  i<16;i++)   temp[i+itr] ^= encryptData[cbcitr++];

        }
        *encryptDataLen = eitr;

    return success;

}

status AES256_CBC_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){

	uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, cbcitr=0;

	if(arrsize % 16 != 0) newarr = ((arrsize / 16) + 1); else newarr = (arrsize / 16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize];

/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/

        for(int i =0 ;  i<16;i++)   temp[i] ^=  IV[i];

        for(int i=0; i < newarr; i++){
            for(int k=0; k < 16; k++){
                bre[k] = temp[itr++];
            }

            encrypt(dim4(bre), 14, round_key256);
            for(uint8_t r=0; r<4;r++)   for(uint8_t c=0; c<4;c++)   encryptData[eitr++] = state[c][r];
            for(int i =0 ;  i<16;i++)   temp[i+itr] ^= encryptData[cbcitr++];

        }
        *encryptDataLen = eitr;

    return success;

}

status AES128_CFB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, epitr=16;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize + 16], iptr=0;

/*********************************************************PKCS#7***************************************************************************/
        for(int pi=0;pi<16;pi++) temp[pi] = IV[pi];
        for(int p=16;p<arrsize+16;p++) temp[p] = arr[p-16];

        if(arrsize%16 != 0)
        	for(int ki=arrsize+16;ki < arrtotsize+16;ki++)
        		temp[ki] = (16 - (arrsize % 16));

/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){
        	if(i==0)
        		for(int k=0; k < 16; k++)	bre[k] = temp[k];
        	else
        		for(int ke=0; ke < 16; ke++)	bre[ke] = encryptData[itr++];

            encrypt(dim4(bre), 10, round_key128);

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];
            for(int ip =0 ;  ip<16; ip++) {
            	printf("before : encryptdata[%d] ->  0x%02X | arr[%d] -> 0x%02X\r\n",iptr, encryptData[iptr], epitr, arr[epitr]);
            	encryptData[iptr++] ^= temp[epitr++ ];
            	printf("after : encryptdata[%d] ^ arr[%d]- > 0x%02X\r\n", iptr, epitr, encryptData[iptr]);
            }
        }

        *encryptDataLen = eitr;

    return success;
}

status AES192_CFB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, epitr=16;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize + 16], iptr=0;

/*********************************************************PKCS#7***************************************************************************/
        for(int pi=0;pi<16;pi++) temp[pi] = IV[pi];
        for(int p=16;p<arrsize+16;p++) temp[p] = arr[p-16];

        if(arrsize%16 != 0)
        	for(int ki=arrsize+16;ki < arrtotsize+16;ki++)
        		temp[ki] = (16 - (arrsize % 16));

/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){
        	if(i==0)
        		for(int k=0; k < 16; k++)	bre[k] = temp[k];
        	else
        		for(int ke=0; ke < 16; ke++)	bre[ke] = encryptData[itr++];

            encrypt(dim4(bre), 12, round_key192);

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];
            for(int ip =0 ;  ip<16; ip++) {
            	printf("before : encryptdata[%d] ->  0x%02X | arr[%d] -> 0x%02X\r\n",iptr, encryptData[iptr], epitr, arr[epitr-1]);
            	encryptData[iptr++] ^= temp[epitr++ ];
            	printf("after : encryptdata[%d] ^ arr[%d]- > 0x%02X\r\n", iptr, epitr, encryptData[iptr]);
            }
        }

        *encryptDataLen = eitr;

    return success;
}

status AES256_CFB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){

	uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, epitr=16, iptr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize + 16];

/*********************************************************PKCS#7***************************************************************************/
        for(int pi=0;pi<16;pi++) temp[pi] = IV[pi];
        for(int p=16;p<arrsize+16;p++) temp[p] = arr[p-16];
        if(arrsize%16 != 0)
        	for(int ki=arrsize+16;ki < arrtotsize+16;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){
        	if(i==0)
        		for(int k=0; k < 16; k++)	bre[k] = temp[k];
        	else
        		for(int ke=0; ke < 16; ke++)	bre[ke] = encryptData[itr++];

            encrypt(dim4(bre), 14, round_key256);

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];
            for(int ip =0 ;  ip<16; ip++) {
            	printf("before : encryptdata[%d] ->  0x%02X | arr[%d] -> 0x%02X\r\n",iptr, encryptData[iptr], epitr, arr[epitr-1]);
            	encryptData[iptr++] ^= temp[epitr++ ];
            	printf("after : encryptdata[%d] ^ arr[%d]- > 0x%02X\r\n", iptr, epitr, encryptData[iptr]);
            }
        }

        *encryptDataLen = eitr;

    return success;
}

status AES128_OFB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, epitr=16;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize + 16], iptr=0, endata[arrtotsize + 16];

/*********************************************************PKCS#7***************************************************************************/
        for(int pi=0;pi<16;pi++) temp[pi] = IV[pi];

        for(int p=16;p<arrsize+16;p++) temp[p] = arr[p-16];

        if(arrsize%16 != 0)
        	for(int ki=arrsize+16;ki < arrtotsize+16;ki++)
        		temp[ki] = (16 - (arrsize % 16));

/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){
        	if(i==0)
        		for(int k=0; k < 16; k++)	bre[k] = temp[k];
        	else
        		for(int ke=0; ke < 16; ke++)	bre[ke] = endata[itr++];

            encrypt(dim4(bre), 10, round_key128);

            for(uint8_t r=0; r<4;r++){
            	for(uint8_t c=0; c<4;c++){
            		encryptData[eitr++] = state[c][r];
            		endata[eitr-1] = encryptData[eitr-1];
            		printf("eitr - > %d\r\n", eitr);
            	}
            }

            for(int ip =0 ;  ip<16; ip++) {
            	printf("before : encryptdata[%d] ->  0x%02X | arr[%d] -> 0x%02X\r\n",iptr, encryptData[iptr], epitr, arr[epitr]);
            	encryptData[iptr++] ^= temp[epitr++];
            	printf("after : encryptdata[%d] ^ arr[%d]- > 0x%02X\r\n", iptr, epitr, encryptData[iptr]);
            }
        }

        *encryptDataLen = eitr;

    return success;
}

status AES192_OFB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, epitr=16;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize + 16], iptr=0, endata[arrtotsize + 16];

/*********************************************************PKCS#7***************************************************************************/
        for(int pi=0;pi<16;pi++) temp[pi] = IV[pi];

        for(int p=16;p<arrsize+16;p++) temp[p] = arr[p-16];

        if(arrsize%16 != 0)
        	for(int ki=arrsize+16;ki < arrtotsize+16;ki++)
        		temp[ki] = (16 - (arrsize % 16));

/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){
        	if(i==0)
        		for(int k=0; k < 16; k++)	bre[k] = temp[k];
        	else
        		for(int ke=0; ke < 16; ke++)	bre[ke] = endata[itr++];

            encrypt(dim4(bre), 12, round_key192);

            for(uint8_t r=0; r<4;r++){
            	for(uint8_t c=0; c<4;c++){
            		encryptData[eitr++] = state[c][r];
            		endata[eitr-1] = encryptData[eitr-1];
            		printf("eitr - > %d\r\n", eitr);
            	}
            }

            for(int ip =0 ;  ip<16; ip++) {
            	printf("before : encryptdata[%d] ->  0x%02X | arr[%d] -> 0x%02X\r\n",iptr, encryptData[iptr], epitr, arr[epitr]);
            	encryptData[iptr++] ^= temp[epitr++];
            	printf("after : encryptdata[%d] ^ arr[%d]- > 0x%02X\r\n", iptr, epitr, encryptData[iptr]);
            }
        }

        *encryptDataLen = eitr;

    return success;
}

status AES256_OFB_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0,newarr=0, epitr=16;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint8_t temp[arrtotsize + 16], iptr=0, endata[arrtotsize + 16];

/*********************************************************PKCS#7***************************************************************************/
        for(int pi=0;pi<16;pi++) temp[pi] = IV[pi];

        for(int p=16;p<arrsize+16;p++) temp[p] = arr[p-16];

        if(arrsize%16 != 0)
        	for(int ki=arrsize+16;ki < arrtotsize+16;ki++)
        		temp[ki] = (16 - (arrsize % 16));

/********************************************************************************************************************************************/

        for(int i=0; i< newarr; i++){
        	if(i==0)
        		for(int k=0; k < 16; k++)	bre[k] = temp[k];
        	else
        		for(int ke=0; ke < 16; ke++)	bre[ke] = endata[itr++];

            encrypt(dim4(bre), 14, round_key256);

            for(uint8_t r=0; r<4;r++){
            	for(uint8_t c=0; c<4;c++){
            		encryptData[eitr++] = state[c][r];
            		endata[eitr-1] = encryptData[eitr-1];
            		printf("eitr - > %d\r\n", eitr);
            	}
            }

            for(int ip =0 ;  ip<16; ip++) {
            	printf("before : encryptdata[%d] ->  0x%02X | arr[%d] -> 0x%02X\r\n",iptr, encryptData[iptr], epitr, arr[epitr]);
            	encryptData[iptr++] ^= temp[epitr++];
            	printf("after : encryptdata[%d] ^ arr[%d]- > 0x%02X\r\n", iptr, epitr, encryptData[iptr]);
            }
        }

        *encryptDataLen = eitr;

    return success;
}

status AES128_CTR_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *CTR,uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, eitr=0,newarr=0, epitr=0, iptr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint16_t value = 0;

    uint8_t temp[arrtotsize], ctrtemp[16];

        for(int p=0;p<16;p++){
        	ctrtemp[p] = CTR[p];
        }
/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/
        for(int i=0; i< newarr; i++){

            for(int k=0; k < 16; k++){
            	bre[k] = ctrtemp[k];
            	printf("bre[%d] -> 0x%02X\r\n", k, bre[k]);
            }

            encrypt(dim4(bre), 10, round_key128);

            value = (ctrtemp[14] << 8) | ctrtemp[15];	value ++;
			ctrtemp[14] = (value >> 8) & 0xFF;	ctrtemp[15] = value & 0xFF;

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];

			for(int ip =0 ;  ip<16; ip++) printf("encrypt data [%d] 0x%02X \r\n", (eitr-16)+ip, encryptData[eitr-16+ip]);


			for(int ip =0 ;  ip<16; ip++) {
				encryptData[iptr++] ^= temp[epitr++];
			}

        }


        *encryptDataLen = eitr;

    return success;

}

status AES192_CTR_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *CTR,uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, eitr=0, newarr=0, epitr=0, iptr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint16_t value = 0;

    uint8_t temp[arrtotsize], ctrtemp[16];

        for(int p=0;p<16;p++){
        	ctrtemp[p] = CTR[p];
        }
/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/
        for(int i=0; i< newarr; i++){

            for(int k=0; k < 16; k++){
            	bre[k] = ctrtemp[k];
            	printf("bre[%d] -> 0x%02X\r\n", k, bre[k]);
            }

            encrypt(dim4(bre), 12, round_key192);

            value = (ctrtemp[14] << 8) | ctrtemp[15];	value ++;
			ctrtemp[14] = (value >> 8) & 0xFF;	ctrtemp[15] = value & 0xFF;

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];

			for(int ip =0 ;  ip<16; ip++) printf("encrypt data [%d] 0x%02X \r\n", (eitr-16)+ip, encryptData[eitr-16+ip]);


			for(int ip =0 ;  ip<16; ip++) {
				encryptData[iptr++] ^= temp[epitr++];
			}

        }


        *encryptDataLen = eitr;

    return success;
}

status AES256_CTR_EN(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *CTR,uint8_t *encryptData, size_t *encryptDataLen){
    uint8_t bre[16] = {0}, eitr=0, newarr=0, epitr=0, iptr=0;

	if(arrsize%16 != 0) newarr = ((arrsize/16)+1); else newarr = (arrsize/16);

    uint32_t arrtotsize = (16 * newarr);

    uint16_t value = 0;

    uint8_t temp[arrtotsize], ctrtemp[16];

        for(int p=0;p<16;p++){
        	ctrtemp[p] = CTR[p];
        }
/*********************************************************PKCS#7***************************************************************************/
        for(int p=0;p<arrsize;p++) temp[p] = arr[p];

        if(arrsize%16 != 0)
        	for(int ki=arrsize;ki < arrtotsize;ki++)
        		temp[ki] = (16 - (arrsize % 16));
/********************************************************************************************************************************************/
        for(int i=0; i< newarr; i++){

            for(int k=0; k < 16; k++){
            	bre[k] = ctrtemp[k];
            	printf("bre[%d] -> 0x%02X\r\n", k, bre[k]);
            }

            encrypt(dim4(bre), 14, round_key256);

            value = (ctrtemp[14] << 8) | ctrtemp[15];	value ++;
			ctrtemp[14] = (value >> 8) & 0xFF;	ctrtemp[15] = value & 0xFF;

            for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	encryptData[eitr++] = state[c][r];

			for(int ip =0 ;  ip<16; ip++) printf("encrypt data [%d] 0x%02X \r\n", (eitr-16)+ip, encryptData[eitr-16+ip]);


			for(int ip =0 ;  ip<16; ip++) {
				encryptData[iptr++] ^= temp[epitr++];
			}

        }


        *encryptDataLen = eitr;

    return success;
}


status AES128_Encrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){

    keyExpansion128(dim4(key));

/*********************************************************AES_ECB_ENC***************************************************************************/
    if(mode == AES_ECB_ENC)
    	AES128_ECB_EN(mode, arr, arrsize, key, encryptData, encryptDataLen);

/*********************************************************AES_CBC_ENC***************************************************************************/
    if(mode == AES_CBC_ENC)
    	AES128_CBC_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_CFB_ENC***************************************************************************/
    if(mode == AES_CFB_ENC)
    	AES128_CFB_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_OFB_ENC***************************************************************************/
    if(mode == AES_OFB_ENC)
    	AES128_OFB_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_CTR_ENC***************************************************************************/
	if(mode == AES_CTR_ENC)
		AES128_CTR_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

	return success;
}

status AES192_Encrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){

	keyExpansion192(dim6(key));

/*********************************************************AES_ECB_ENC***************************************************************************/
    if(mode == AES_ECB_ENC)
    	AES192_ECB_EN(mode, arr, arrsize, key, encryptData, encryptDataLen);

/*********************************************************AES_CBC_ENC***************************************************************************/
    if(mode == AES_CBC_ENC)
    	AES192_CBC_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_CFB_ENC***************************************************************************/
	if(mode == AES_CFB_ENC)
		AES192_CFB_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_OFB_ENC***************************************************************************/
	if(mode == AES_OFB_ENC)
		AES192_OFB_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_CTR_ENC***************************************************************************/
	if(mode == AES_CTR_ENC)
		AES192_CTR_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);
    return success;
}

status AES256_Encrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *encryptData, size_t *encryptDataLen){

    keyExpansion256(dim8(key));

/*********************************************************AES_ECB_ENC***************************************************************************/
	if(mode == AES_ECB_ENC)
		AES256_ECB_EN(mode, arr, arrsize, key, encryptData, encryptDataLen);

/*********************************************************AES_CBC_ENC***************************************************************************/
	if(mode == AES_CBC_ENC)
		AES256_CBC_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_CFB_ENC***************************************************************************/
	if(mode == AES_CFB_ENC)
		AES256_CFB_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_OFB_ENC***************************************************************************/
	if(mode == AES_OFB_ENC)
		AES256_OFB_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

/*********************************************************AES_CTR_ENC***************************************************************************/
	if(mode == AES_CTR_ENC)
		AES256_CTR_EN(mode, arr, arrsize, key, IV,  encryptData, encryptDataLen);

	return success;
}
