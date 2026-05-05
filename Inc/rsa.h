/*
 * rsa.h
 *
 *  Created on: May 5, 2026
 *      @author: Srivisweswara Mohan Santhi
 */

#ifndef RSA_H_
#define RSA_H_

#include "main.h"

typedef uint64_t rsal;

rsal prime(rsal n);
rsal encryptKey(rsal z);
rsal decryptKey(rsal e, rsal phi);
rsal modexp(rsal base, rsal exp, rsal mod);
rsal encodeMsg(char* msg, rsal e, rsal N, rsal* out);
void decodeMsg(rsal* cipher, int len, rsal d, rsal N, char* out);


#endif /* RSA_H_ */
