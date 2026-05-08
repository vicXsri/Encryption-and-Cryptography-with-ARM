#include "aes.h"

extern uint8_t s_box[16][16];

uint8_t roundCons[15] = {
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36, 0x6C, 0xD8,
    0xAB,  0x4D, 0x9A

};

uint8_t round_key128[11][4][4]={0x00};
uint8_t round_key192[13][4][4]={0x00};
uint8_t round_key256[15][4][4]={0x00};

int gf(int a, int b) {
  int p = 0;
  for (int i = 0; i < 8; i++) {
     if ((b & 1) != 0) {
        p ^= a;
     }
     int high = a & 0x80;
     a <<= 1;
     if (high != 0) {
        a ^= 0x1B;
     }
     b >>= 1;
  }
  return p;
}

void KeyRotWord(uint8_t *x){
    uint8_t t = x[0];
    x[0] = x[1];
    x[1] = x[2];
    x[2] = x[3];
    x[3] = t;
}

uint8_t KeySubBytes(uint8_t x){
    return s_box[((x >> 4) & 0x0F)][(x & 0x0F)];
}

void KeySubWord(uint8_t x[4]){
    x[0] = KeySubBytes(x[0]);
    x[1] = KeySubBytes(x[1]);
    x[2] = KeySubBytes(x[2]);
    x[3] = KeySubBytes(x[3]);
}

uint8_t (*dim4(uint8_t *tex))[4]{
    static uint8_t m4[4][4];

    for(int i=0;i<4;i++){
    	m4[i][0] = tex[i];
    	m4[i][1] = tex[i+4];
    	m4[i][2] = tex[i+8];
    	m4[i][3] = tex[i+12];
    }

    return m4;
}

uint8_t (*dim6(uint8_t *tex))[6]{
    static uint8_t m6[4][6];

    for(int i=0;i<4;i++){
    	m6[i][0] = tex[i];
    	m6[i][1] = tex[i+4];
    	m6[i][2] = tex[i+8];
    	m6[i][3] = tex[i+12];
    	m6[i][4] = tex[i+16];
    	m6[i][5] = tex[i+20];
    }

    return m6;
}

uint8_t (*dim8(uint8_t *tex))[8]{
    static uint8_t m8[4][8];

    for(int i=0;i<4;i++){
    	m8[i][0] = tex[i];
    	m8[i][1] = tex[i+4];
    	m8[i][2] = tex[i+8];
    	m8[i][3] = tex[i+12];
    	m8[i][4] = tex[i+16];
    	m8[i][5] = tex[i+20];
    	m8[i][6] = tex[i+24];
    	m8[i][7] = tex[i+28];
    }

    return m8;
}

status keyExpansion128(uint8_t (*key)[4]){
    for(int i=0; i<4;i++)   for(int j=0; j<4; j++) round_key128[0][i][j] = key[i][j];

    for(int rou=1; rou<=10;rou++){
        uint8_t temp[4];

        temp[0] = round_key128[rou-1][0][3];
        temp[1] = round_key128[rou-1][1][3];
        temp[2] = round_key128[rou-1][2][3];
        temp[3] = round_key128[rou-1][3][3];

        KeyRotWord(temp);
        KeySubWord(temp);
        temp[0] ^= roundCons[rou-1];

        for(int row =0; row< 4; row++){
        	round_key128[rou][row][0] = round_key128[rou-1][row][0] ^ temp[row];
        }

        for(int row =0; row< 4; row++){
        	round_key128[rou][row][1] = round_key128[rou-1][row][1] ^ round_key128[rou][row][0];
        }

        for(int row =0; row< 4; row++){
        	round_key128[rou][row][2] = round_key128[rou-1][row][2] ^ round_key128[rou][row][1];
        }

        for(int row =0; row< 4; row++){
        	round_key128[rou][row][3] = round_key128[rou-1][row][3] ^ round_key128[rou][row][2];
        }
    }

    return success;
}

status keyExpansion192(uint8_t key[4][6])
{
    const int Nk = 6; const int Nr = 12; const int totalWords = 4 * (Nr + 1);

    uint8_t W[52][4];

    for (int c = 0; c < Nk; c++)
        for (int r = 0; r < 4; r++)
            W[c][r] = key[r][c];

    uint8_t temp[4];

    for (int i = Nk; i < totalWords; i++)
    {
        temp[0] = W[i-1][0];
        temp[1] = W[i-1][1];
        temp[2] = W[i-1][2];
        temp[3] = W[i-1][3];

        if (i % Nk == 0)
        {
            KeyRotWord(temp);
            KeySubWord(temp);
            temp[0] ^= roundCons[(i / Nk) - 1];
        }

        W[i][0] = W[i-Nk][0] ^ temp[0];
        W[i][1] = W[i-Nk][1] ^ temp[1];
        W[i][2] = W[i-Nk][2] ^ temp[2];
        W[i][3] = W[i-Nk][3] ^ temp[3];
    }
    for (int r = 0; r <= Nr; r++)
    {
        for (int c = 0; c < 4; c++)
        {
            int wIndex = r * 4 + c;
            round_key192[r][0][c] = W[wIndex][0];
            round_key192[r][1][c] = W[wIndex][1];
            round_key192[r][2][c] = W[wIndex][2];
            round_key192[r][3][c] = W[wIndex][3];
        }
    }
    return success;
}

status keyExpansion256(uint8_t key[4][8])
{
    const int Nk = 8;
    const int Nr = 14; const int totalWords = 4 * (Nr + 1);
    uint8_t W[60][4];

    for (int c = 0; c < Nk; c++)
        for (int r = 0; r < 4; r++)
            W[c][r] = key[r][c];

    uint8_t temp[4];
    for (int i = Nk; i < totalWords; i++)
    {
        temp[0] = W[i-1][0];
        temp[1] = W[i-1][1];
        temp[2] = W[i-1][2];
        temp[3] = W[i-1][3];
        if (i % Nk == 0 )
        {
            KeyRotWord(temp);
            KeySubWord(temp);
            temp[0] ^= roundCons[(i / Nk) - 1];
        }else if(i % 8 == 4){
            KeySubWord(temp);
        }
        W[i][0] = W[i-Nk][0] ^ temp[0];
        W[i][1] = W[i-Nk][1] ^ temp[1];
        W[i][2] = W[i-Nk][2] ^ temp[2];
        W[i][3] = W[i-Nk][3] ^ temp[3];
    }
    for (int r = 0; r <= Nr; r++)
    {
        for (int c = 0; c < 4; c++)
        {
            int wIndex = r * 4 + c;
            round_key256[r][0][c] = W[wIndex][0];
            round_key256[r][1][c] = W[wIndex][1];
            round_key256[r][2][c] = W[wIndex][2];
            round_key256[r][3][c] = W[wIndex][3];
        }
    }

    return success;
}
