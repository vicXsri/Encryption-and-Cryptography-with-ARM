/*
 * rng_soft.h
 *
 *  Created on: May 8, 2026
 *      @author: Srivisweswara Mohan Santhi
 */

#ifndef INC_RNG_SOFT_H_
#define INC_RNG_SOFT_H_

#include "main.h"

typedef struct{
		uint32_t s[4];
}RNG_STATETypedef;

void RNGSeed(RNG_STATETypedef* st, uint32_t a,  uint32_t b, uint32_t c, uint32_t d);
uint32_t RNGGetu32(RNG_STATETypedef* st);
void RNGByte(RNG_STATETypedef* st, uint8_t * out, uint8_t len);

#endif /* INC_RNG_SOFT_H_ */
