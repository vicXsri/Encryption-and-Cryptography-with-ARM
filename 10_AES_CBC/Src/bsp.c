/*
 * bsp.c
 *
 *  Created on: Apr 13, 2025
 *      Author: Vichu
 */

#include "bsp.h"

void led_init(void){
	/*Enable clock access - portA*/
	RCC->AHB1ENR |= GPIOAEN;
	/*Set PA5 to output mode*/
	GPIOA->MODER |= (1U << 10);
	GPIOA->MODER &=~ (1U << 11);
}
void led_on(void){
	/*Set PA5 to high*/
	GPIOA->ODR |= LEDPIN;
}
void led_off(void){
	/*Set PA5 to low*/
	GPIOA->ODR &=~ LEDPIN;
}
void button_init(void){
	/*Enable clock access - portC*/
	RCC->AHB1ENR |= GPIOCEN;

	/*Set PC13 to input mode*/
	GPIOC->MODER &=~ (1U << 26);
	GPIOC->MODER &=~ (1U << 27);
}

bool get_btn_state(void){
	/*check if button is pressed*/
	if(GPIOC->IDR & BTNPIN)	return false;
	else	return true;


}
