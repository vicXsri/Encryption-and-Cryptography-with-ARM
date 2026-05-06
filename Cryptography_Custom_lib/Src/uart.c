/*
 * uart.c
 *
 *  Created on: Apr 1, 2025
 *      Author: Vichu
 */

#include "uart.h"

#define uart_baudrate 		115200
#define apb1_clock			16000000
#define status				(1U<<7)

int __io_putchar(int ch){
	debug(ch);
	return ch;
}

void debug_uart_init(void){
	/*Enable clock access to GPIOA*/
	RCC->AHB1ENR |= (1U<<0);
	/*Set the mode of PA2 to alternate function mode*/
	GPIOA->MODER &=~ (1U<<4);
	GPIOA->MODER |=  (1U<<5);
	/*Set alternate function type to AF7(UART2_TX)*/
	GPIOA->AFR[0] |=  (1U<<8);
	GPIOA->AFR[0] |=  (1U<<9);
	GPIOA->AFR[0] |=  (1U<<10);
	GPIOA->AFR[0] &=~ (1U<<11);

	/*Enable clock access to UART2*/
	RCC->APB1ENR |=   (1U<<17);
	/*Configure uart baudrate*/
	USART2->BRR = compute_uart_baud(apb1_clock,uart_baudrate);
	/*configure transfer direction*/
	USART2->CR1 = (1U<<3);
	/*Enable uart module*/
	USART2->CR1 |= (1U<<13);

}
void debug(int ch){
	 /*Make sure transmit data register is empty*/
	 while(!(USART2->SR & status)){}
	 /*Write to transmit data register*/
	 USART2->DR = (ch & 0xFF);
}
uint16_t compute_uart_baud(uint32_t perip_clk, uint32_t baud){
	return ((perip_clk + (baud/2U))/baud);
}


