/*
 * rng_soft.c
 *
 *  Created on: May 8, 2026
 *      @author: Srivisweswara Mohan Santhi
 */

#include "rng_soft.h"

/* XORShift128 */

void RNGSeed(RNG_STATETypedef* st, uint32_t a,  uint32_t b, uint32_t c, uint32_t d){

	st->s[0] = a;
	st->s[1] = b;
	st->s[2] = c;
	st->s[3] = d;


	if((a | b | c | d) == 0){
        st->s[0] = 0x12345678;
        st->s[1] = 0x87654321;
        st->s[2] = 0xA5A5A5A5;
        st->s[3] = 0x5A5A5A5A;
	}

}

uint32_t RNGGetu32(RNG_STATETypedef* st){

	uint32_t t = st->s[3];
	uint32_t s = st->s[0];

	st->s[3] = st->s[2];
	st->s[2] = st->s[1];
	st->s[1] = s;

	t ^= t << 12;
	t ^= t >> 8;

	st->s[0] = t ^ s ^ (s >> 19);

	return st->s[0];

}

void RNGByte(RNG_STATETypedef* st, uint8_t * out, uint8_t len){

	uint32_t r = 0;

	for(uint32_t i = 0; i < len; i++){

		if((i & 3U)  == 0)	r = RNGGetu32(st);

		out[i] = (uint8_t) (r >> (24 - 8 * (i & 3U)));

	}
}
