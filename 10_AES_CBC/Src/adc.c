/*
 * adc.c
 *
 *  Created on: Feb 10, 2026
 *      Author: Vichu
 */


#include "adc.h"


void pa1_adc_init(void){

	/*Configure the ADC GPIO Pin*/

	/*Enable clock access to GPIOA*/
	RCC->AHB1ENR |= GPIOAEN;

	/*Set PA1 mode to analog mode*/
	GPIOA->MODER |= (0x3U << 2);

	/*Configure the ADC Module*/

	/*Enable clock access to the ADC module*/
	RCC->APB2ENR |= (1U << 8);

	/*Set the Conversion Sequence start*/
	ADC1->SQR3 |= (1U << 0);

	/*Set the Conversion Sequence length*/
	ADC1->SQR1 =  0x00;
	/*Enable ADC Module*/
	ADC1->CR2 |= (1U << 0);

}

void start_conversion(void){

	/*Enable continuous Conversion*/
	ADC1->CR2 |= (1U << 1);

	/*Start AD Conversion*/
	ADC1->CR2 |= (1U << 30);

}

uint32_t adc_read(void){

	/*Wait for conversion to be complete*/
	while(!(ADC1->SR & (1U <<1))){}

	/*Read Converted Values*/
	return (ADC1->DR);
}
