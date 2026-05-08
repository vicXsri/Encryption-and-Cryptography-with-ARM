/*
 * implementation.h
 *
 *  Created on: Mar 26, 2026
 *      @author: Srivisweswara Mohan Santhi
 */

#ifndef IMPLEMENTATION_H_
#define IMPLEMENTATION_H_

#include "main.h"

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

void RSA();

#define length_rsa  1000
void outputprint(size_t length, uint8_t *data);


#endif /* IMPLEMENTATION_H_ */
