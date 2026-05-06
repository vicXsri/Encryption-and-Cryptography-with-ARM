/*
 * uart.h
 *
 *  Created on: Apr 1, 2025
 *      Author: Vichu
 */

#ifndef UART_H_
#define UART_H_

#include "main.h"
void debug_uart_init(void);
static void debug(int ch);
static uint16_t compute_uart_baud(uint32_t perip_clk, uint32_t baud);
#endif /* UART_H_ */
