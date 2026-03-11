/*
 * main.h
 *
 *  Created on: Mar 31, 2025
 *      Author: Vichu
 */

#ifndef MAIN_H_
#define MAIN_H_

#include "stm32f4xx.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>

typedef enum{
    success = 0x00U,
    error   = 0x01U,
    busy    = 0x02U,
    timeout = 0x03U
}status;

#include "fpu.h"
#include "uart.h"
#include "timebase.h"
#include "bsp.h"
#include "adc.h"
#include "caesar_cipher.h"
#include "monoalphabetic_cipher.h"
#include "vigenere_cipher.h"
#include "cmox_crypto.h"
#include "aes.h"
#include "aesEncrypt.h"
#include "aesDecrypt.h"
#endif /* MAIN_H_ */
