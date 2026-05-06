/*
 * rsa.c
 *
 *  Created on: May 5, 2026
 *      @author: Srivisweswara Mohan Santhi
 */


#include "rsa.h"

rsal j=0;
rsal f;

rsal modexp(rsal base, rsal exp, rsal mod){
    rsal result = 1;
    base = base % mod;

    while(exp > 0){
        if(exp & 1)
            result = (result * base) % mod;

        exp >>= 1;
        base = (base * base) % mod;
    }

    return result;
}

rsal prime(rsal n){
    if(n < 2) return 0;
    for(rsal i = 2; i * i <= n; i++){
        if(n % i == 0) return 0;
    }
    return 1;
}

rsal gcd(rsal a, rsal b) {
    while (b != 0) {
        rsal temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

rsal cPrime(rsal arr[], rsal N, rsal z){
    for(rsal i = 0; i < f; i++){
       if((gcd(N,arr[i]) == 1) && (gcd(z,arr[i]) == 1))
       if(gcd(N, arr[i]) == 1)return arr[i];
    }
    return -1;
}

rsal gcdExtended(rsal a, rsal b, rsal *x, rsal *y) {
    if (b == 0) {
        *x = 1;
        *y = 0;
        return a;
    }
    rsal x1, y1;
    rsal g = gcdExtended(b, a % b, &x1, &y1);

    *x = y1;
    *y = x1 - (a / b) * y1;
    return g;
}

rsal encryptKey(rsal phi){
    rsal e = 3;

    while(e < phi){
        if(gcd(e, phi) == 1)
            return e;
        e += 2;
    }

    return -1;
}

rsal decryptKey(rsal e, rsal phi) {
    rsal x, y;
    rsal g = gcdExtended(e, phi, &x, &y);

    if (g != 1)
        return -1;

    x %= phi;
    if (x < 0) x += phi;

    return x;
}

rsal encodeMsg(char* msg, rsal e, rsal N, rsal* out){
    int i = 0;

    while(msg[i] != '\0'){
        rsal m = msg[i];      // convert char → number
        out[i] = modexp(m, e, N);  // RSA encryption
        i++;
    }

    return i;   // return length
}

void decodeMsg(rsal* cipher, int len, rsal d, rsal N, char* out){
    for(int i = 0; i < len; i++){
        rsal m = modexp(cipher[i], d, N);  // RSA decryption
        out[i] = (char)m;                 // convert number → char
    }
    out[len] = '\0';  // null-terminate string
}
