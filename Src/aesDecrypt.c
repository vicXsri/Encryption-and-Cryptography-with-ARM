#include "aesDecrypt.h"


uint8_t inv_s_box[16][16] = {
    {0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB},
    {0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB},
    {0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E},
    {0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25},
    {0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92},
    {0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84},
    {0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06},
    {0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B},
    {0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73},
    {0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E},
    {0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B},
    {0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4},
    {0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F},
    {0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF},
    {0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61},
    {0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D}
};
uint8_t eds_box[16][16] = {{0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
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


uint8_t invstate[4][4] = {0x00};
extern uint8_t state[4][4];

extern uint8_t round_key128[11][4][4];
extern uint8_t round_key192[13][4][4];
extern uint8_t round_key256[15][4][4];

/* Substitution Bytes | Forward Substitution Bytes */
status InvSubBytes(const uint8_t (*arr)[4]){
    for(int i=0; i<4; i++)
        for(int j=0; j<4; j++)
            invstate[i][j] = inv_s_box[((arr[i][j] >> 4) & 0x0F)][(arr[i][j] & 0x0F)];
    
    return success;
}

status InvShiftRows(const uint8_t (*arr)[4]){

    uint8_t temp = arr[3][0];
    invstate[3][0]  = arr[3][1];
    invstate[3][1]  = arr[3][2];
    invstate[3][2]  = arr[3][3];
    invstate[3][3]  = temp;

    uint8_t temp0 = arr[2][0];
    uint8_t temp1 = arr[2][1];
    invstate[2][0]   = arr[2][2];
    invstate[2][1]   = arr[2][3];
    invstate[2][2]   = temp0;
    invstate[2][3]   = temp1;

    temp        = arr[1][3];
    invstate[1][3] = arr[1][2];
    invstate[1][2] = arr[1][1];
    invstate[1][1] = arr[1][0];
    invstate[1][0] = temp;
    
    return success;
}

status InvMixColumns(const uint8_t (*arr)[4])
{
    uint8_t col[4];

    for (int c = 0; c < 4; c++)
    {
        col[0] = invstate[0][c];
        col[1] = invstate[1][c];
        col[2] = invstate[2][c];
        col[3] = invstate[3][c];

        invstate[0][c] =
              gf(0x0E, col[0])
            ^ gf(0x0B, col[1])
            ^ gf(0x0D ,col[2])
            ^ gf(0x09 ,col[3]);

        invstate[1][c] =
              gf(0x09 ,col[0])
            ^ gf(0x0E, col[1])
            ^ gf(0x0B, col[2])
            ^ gf(0x0D ,col[3]);

        invstate[2][c] =
              gf(0x0D ,col[0])
            ^ gf(0x09 ,col[1])
            ^ gf(0x0E, col[2])
            ^ gf(0x0B, col[3]);

        invstate[3][c] =
              gf(0x0B, col[0])
            ^ gf(0x0D ,col[1])
            ^ gf(0x09 ,col[2])
            ^ gf(0x0E, col[3]);
    }

    return success;
}

status InvAddRoundKey(const uint8_t (*arr)[4], const uint8_t (*key)[4]){
     for(int i=0; i<4; i++){
        for(int j=0; j<4; j++){
            invstate[i][j] = arr[i][j] ^ key[i][j];
        }
    }
    
    return success;
}

status decrypt(uint8_t (*arr)[4], uint8_t round, uint8_t round_key[][4][4]){
    uint8_t itr=0;
    printf("preaddRoundKey\r\n");
    (InvAddRoundKey(arr, round_key[round]) != success)?            printf("AddRoundKey Failed\r\n"):
                                                            printf("AddRoundKey Success\r\n");
    printf("Round - %d\r\n", ++itr);
    (InvSubBytes(invstate) != success)?                           printf("SubBytes Failed\r\n"):
                                                            printf("SubBytes Success\r\n");
    (InvShiftRows(invstate) != success)?                          printf("ShiftRows Failed\r\n"):
                                                            printf("ShiftRows Success\r\n");

    for(int i=(round-1); i>=1; i--){
        printf("Round - %d\r\n", itr++);
        (InvAddRoundKey(invstate, round_key[i]) != success)?      printf("AddRoundKey Failed\r\n"):
                                                            printf("AddRoundKey Success\r\n");
        (InvMixColumns(invstate) != success)?                     printf("MixColumns Failed\r\n"):
                                                            printf("MixColumns Success\r\n");
        (InvSubBytes(invstate) != success)?                       printf("SubBytes Failed\r\n"):
                                                            printf("SubBytes Success\r\n");
        (InvShiftRows(invstate) != success)?                      printf("ShiftRows Failed\r\n"):
                                                            printf("ShiftRows Success\r\n");
    }
    
    (InvAddRoundKey(invstate, round_key[0]) != success)?     printf("AddRoundKey Failed\r\n"):
    															  printf("AddRoundKey Success\r\n");

    return success;
}

status AES128_ECB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, pad=0;

    for(int i=0; i< (arrsize/16); i++){
         for(int k=0; k < 16; k++)	bre[k] = arr[itr++];

         decrypt(dim4(bre), 10, round_key128);

         for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = invstate[c][r];

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				 pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {	*decryptDataLen = eitr;	return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {	*decryptDataLen = eitr;	return success; }}

				*decryptDataLen = eitr - pad;
				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES192_ECB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, pad;

    for(int i=0; i< (arrsize/16); i++){
        for(int k=0; k < 16; k++)	bre[k] = arr[itr++];

        decrypt(dim4(bre), 12, round_key192);

        for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = invstate[c][r];

/*********************************************************PKCS#7***************************************************************************/
        if((arrsize/16) == i+1){
			pad = decryptData[eitr - 1];

			if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

			for (int i = 0; i < pad; i++) {
				if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr;return success;}
			}

			*decryptDataLen = eitr - pad;
			return success;
        }
/********************************************************************************************************************************************/
    }
	return success;

}

status AES256_ECB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, pad=0;

    for(int i=0; i< (arrsize/16); i++){
        for(int k=0; k < 16; k++)	bre[k] = arr[itr++];

        decrypt(dim4(bre), 14, round_key256);

        for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = invstate[c][r];

/*********************************************************PKCS#7***************************************************************************/
        if((arrsize/16) == i+1){
			pad = decryptData[eitr - 1];

			if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

			for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr;return success;}}

			*decryptDataLen = eitr - pad;
			return success;
        }
/********************************************************************************************************************************************/
    }
	return success;
}

status AES128_CBC_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, cbcitr=16, arritr=0, pad=0;

	for(int i=0; i< (arrsize/16); i++){

         for(int k=0; k < 16; k++)	bre[k] = arr[itr++];

         decrypt(dim4(bre), 10, round_key128);

         for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = invstate[c][r];

         if(i==0)
             for(int irf =0; irf<16; irf++)   decryptData[irf] ^=  IV[irf];
         else
             for(int i =0 ;  i<16;i++)	decryptData[cbcitr++] ^= arr[arritr++];

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr;return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr;return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES192_CBC_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, cbcitr=16, arritr=0, pad=0;

	for(int i=0; i< (arrsize/16); i++){

		for(int k=0; k < 16; k++) bre[k] = arr[itr++];

		decrypt(dim4(bre), 12, round_key192);

		for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = invstate[c][r];

        if(i==0)	for(int irf =0; irf<16; irf++)   decryptData[irf] ^=  IV[irf];
        else		for(int i =0 ;  i<16;i++)	decryptData[cbcitr++] ^= arr[arritr++];

/*********************************************************PKCS#7***************************************************************************/
        if((arrsize/16) == i+1){
			pad = decryptData[eitr - 1];

			if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

			for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

			*decryptDataLen = eitr - pad;

			return success;
        }
/********************************************************************************************************************************************/
    }
	return success;

}

status AES256_CBC_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){

	uint8_t bre[16] = {0}, itr=0, eitr=0, cbcitr=16, arritr=0, pad=0;

    for(int i=0; i< (arrsize/16); i++){

    	for(int k=0; k < 16; k++) bre[k] = arr[itr++];

        decrypt(dim4(bre), 14, round_key256);

        for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = invstate[c][r];

        if(i==0)	for(int irf =0; irf<16; irf++)   decryptData[irf] ^=  IV[irf];
        else		for(int i =0 ;  i<16;i++)	decryptData[cbcitr++] ^= arr[arritr++];

/*********************************************************PKCS#7***************************************************************************/
        if((arrsize/16) == i+1){
			pad = decryptData[eitr - 1];

			if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

			for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

			*decryptDataLen = eitr - pad;

			return success;
        }
/********************************************************************************************************************************************/
    }
	return success;

}

status AES128_CFB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, aitr=0, pad=0;

    for(int i=0; i< (arrsize/16); i++){

         if(i==0)	for(int ih=0; ih < 16; ih++)	bre[ih] = IV[ih];
         else 		for(int k=0; k < 16; k++)		bre[k] = arr[itr++];

         encrypt(dim4(bre), 10, round_key128);

         for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++) decryptData[eitr++] = state[c][r];

    	 for(int ih=0; ih < 16; ih++){decryptData[aitr] ^= arr[aitr]; aitr++;}

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr;return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES192_CFB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, aitr=0, pad=0;

    for(int i=0; i< (arrsize/16); i++){

         if(i==0)	for(int ih=0; ih < 16; ih++) bre[ih] = IV[ih];

         else 		for(int k=0; k < 16; k++)	bre[k] = arr[itr++];

         encrypt(dim4(bre), 12, round_key192);

         for(uint8_t r=0; r<4;r++) for(uint8_t c=0; c<4;c++) decryptData[eitr++] = state[c][r];


    	 for(int ih=0; ih < 16; ih++){decryptData[aitr] ^= arr[aitr]; aitr++;}

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES256_CFB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, aitr=0, pad=0;

    for(int i=0; i< (arrsize/16); i++){

         if(i==0)	for(int ih=0; ih < 16; ih++)	bre[ih] = IV[ih];

         else		for(int k=0; k < 16; k++)	bre[k] = arr[itr++];

         encrypt(dim4(bre), 14, round_key256);

         for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = state[c][r];

    	 for(int ih=0; ih < 16; ih++){decryptData[aitr] ^= arr[aitr]; aitr++;}

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES128_OFB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){

	uint8_t bre[16] = {0}, itr=0, eitr=0, aitr=0, endata[arrsize], pad=0;

    for(int i=0; i< (arrsize/16); i++){

         if(i==0)	for(int ih=0; ih < 16; ih++)	bre[ih] = IV[ih];

         else		for(int k=0; k < 16; k++)	bre[k] = endata[itr++];

         encrypt(dim4(bre), 10, round_key128);

         for(uint8_t r=0; r<4;r++){for(uint8_t c=0; c<4;c++){decryptData[eitr++] = state[c][r]; endata[eitr-1] = decryptData[eitr-1];}}

    	 for(int ih=0; ih < 16; ih++){decryptData[aitr] ^= arr[aitr]; aitr++;}

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES192_OFB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, aitr=0, endata[arrsize], pad=0;

    for(int i=0; i< (arrsize/16); i++){

         if(i==0)	for(int ih=0; ih < 16; ih++)	bre[ih] = IV[ih];

         else		for(int k=0; k < 16; k++)	bre[k] = endata[itr++];

         encrypt(dim4(bre), 12, round_key192);

         for(uint8_t r=0; r<4;r++){for(uint8_t c=0; c<4;c++){decryptData[eitr++] = state[c][r]; endata[eitr-1] = decryptData[eitr-1];}}

    	 for(int ih=0; ih < 16; ih++){decryptData[aitr] ^= arr[aitr]; aitr++;}

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES256_OFB_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, itr=0, eitr=0, aitr=0, endata[arrsize], pad=0;

    for(int i=0; i< (arrsize/16); i++){

         if(i==0)	for(int ih=0; ih < 16; ih++) bre[ih] = IV[ih];
         else		for(int k=0; k < 16; k++)	bre[k] = endata[itr++];

         encrypt(dim4(bre), 14, round_key256);

         for(uint8_t r=0; r<4;r++){for(uint8_t c=0; c<4;c++){decryptData[eitr++] = state[c][r]; endata[eitr-1] = decryptData[eitr-1];}}

    	 for(int ih=0; ih < 16; ih++){decryptData[aitr] ^= arr[aitr]; aitr++;}

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr;	return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES128_CTR_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *CTR, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, eitr=0, ctrtemp[16], epitr=0, iptr=0, pad=0;

    uint16_t value = 0;

    for(int p=0;p<16;p++)	ctrtemp[p] = CTR[p];

    for(int i=0; i< (arrsize/16); i++){

         for(int k=0; k < 16; k++)	bre[k] = ctrtemp[k];

         value = (ctrtemp[14] << 8) | ctrtemp[15];	value ++;
         ctrtemp[14] = (value >> 8) & 0xFF;	ctrtemp[15] = value & 0xFF;

         encrypt(dim4(bre), 10, round_key128);

         for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = state[c][r];

         for(int ip =0 ;  ip<16; ip++)	decryptData[iptr++] ^= arr[epitr++];

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;
}

status AES192_CTR_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *CTR, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, eitr=0, ctrtemp[16], epitr=0, iptr=0, pad=0;

    uint16_t value = 0;

    for(int p=0;p<16;p++)	ctrtemp[p] = CTR[p];

    for(int i=0; i< (arrsize/16); i++){

         for(int k=0; k < 16; k++)	bre[k] = ctrtemp[k];

        value = (ctrtemp[14] << 8) | ctrtemp[15];	value ++;
		ctrtemp[14] = (value >> 8) & 0xFF;	ctrtemp[15] = value & 0xFF;

         encrypt(dim4(bre), 12, round_key192);

         for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = state[c][r];

         for(int ip =0 ;  ip<16; ip++)	decryptData[iptr++] ^= arr[epitr++];

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr;	return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;

}

status AES256_CTR_DE(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *CTR, uint8_t *decryptData, size_t *decryptDataLen){
    uint8_t bre[16] = {0}, eitr=0, ctrtemp[16], epitr=0, iptr=0, pad=0;

    uint16_t value = 0;

    for(int p=0;p<16;p++)	ctrtemp[p] = CTR[p];

    for(int i=0; i< (arrsize/16); i++){

         for(int k=0; k < 16; k++)	bre[k] = ctrtemp[k];

         value = (ctrtemp[14] << 8) | ctrtemp[15];	value ++;
         ctrtemp[14] = (value >> 8) & 0xFF;	ctrtemp[15] = value & 0xFF;

         encrypt(dim4(bre), 14, round_key256);

         for(uint8_t r=0; r<4;r++)	for(uint8_t c=0; c<4;c++)	decryptData[eitr++] = state[c][r];

         for(int ip =0 ;  ip<16; ip++)	decryptData[iptr++] ^= arr[epitr++];

/*********************************************************PKCS#7***************************************************************************/
         if((arrsize/16) == i+1){
				pad = decryptData[eitr - 1];

				if (pad == 0 || pad > 16) {*decryptDataLen = eitr; return success;}

				for (int i = 0; i < pad; i++) {if (decryptData[eitr - 1 - i] != pad) {*decryptDataLen = eitr; return success;}}

				*decryptDataLen = eitr - pad;

				return success;
         }
/********************************************************************************************************************************************/
     }
	return success;
}


status AES128_Decrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){

    keyExpansion128(dim4(key));

/*********************************************************AES_ECB_DEC***************************************************************************/

    if(mode == AES_ECB_DEC){
    	AES128_ECB_DE(mode, arr, arrsize, key, decryptData, decryptDataLen);
    	return success;
    }

/*********************************************************AES_CBC_DEC***************************************************************************/

    else if(mode == AES_CBC_DEC){
    	AES128_CBC_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
    	return success;
    }

/*********************************************************AES_CBC_DEC***************************************************************************/

    else if(mode == AES_CFB_DEC){
    	AES128_CFB_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
    	return success;
    }

/*********************************************************AES_CBC_DEC***************************************************************************/

    else if(mode == AES_OFB_DEC){
		AES128_OFB_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
    	return success;
    }

/*********************************************************AES_CTR_DEC***************************************************************************/

    else if(mode == AES_CTR_DEC){
		AES128_CTR_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
    	return success;
    }

	return error;
}

status AES192_Decrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){

    keyExpansion192(dim6(key));

/*********************************************************AES_ECB_DEC***************************************************************************/

	if(mode == AES_ECB_DEC){
		AES192_ECB_DE(mode, arr, arrsize, key, decryptData, decryptDataLen);
		return success;
	}

/*********************************************************AES_CBC_DEC***************************************************************************/

	else if(mode == AES_CBC_DEC){
		AES192_CBC_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}

/*********************************************************AES_CBC_DEC***************************************************************************/

	else if(mode == AES_CFB_DEC){
		AES192_CFB_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}

/*********************************************************AES_CBC_DEC***************************************************************************/

	else if(mode == AES_OFB_DEC){
		AES192_OFB_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}


/*********************************************************AES_CTR_DEC***************************************************************************/

	else if(mode == AES_CTR_DEC){
		AES192_CTR_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}

	return error;

}

status AES256_Decrypt(uint8_t mode, uint8_t *arr, uint32_t arrsize, uint8_t *key, uint8_t *IV, uint8_t *decryptData, size_t *decryptDataLen){

    keyExpansion256(dim8(key));

/*********************************************************AES_ECB_DEC***************************************************************************/

	if(mode == AES_ECB_DEC){
		AES256_ECB_DE(mode, arr, arrsize, key, decryptData, decryptDataLen);
		return success;
	}

/*********************************************************AES_CBC_DEC***************************************************************************/

	if(mode == AES_CBC_DEC){
		AES256_CBC_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}

/*********************************************************AES_CBC_DEC***************************************************************************/

	if(mode == AES_CFB_DEC){
		AES256_CFB_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}

/*********************************************************AES_CBC_DEC***************************************************************************/

	if(mode == AES_OFB_DEC){
		AES256_OFB_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}

/*********************************************************AES_CTR_DEC***************************************************************************/

	if(mode == AES_CTR_DEC){
		AES256_CTR_DE(mode, arr, arrsize, key, IV,decryptData, decryptDataLen);
		return success;
	}

    return error;
}
