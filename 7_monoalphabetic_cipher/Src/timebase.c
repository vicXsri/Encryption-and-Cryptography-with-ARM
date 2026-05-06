/*
 * timebse.c
 *
 *  Created on: Apr 9, 2025
 *      Author: Vichu
 */

#include "timebase.h"
#include "stm32f4xx.h"

volatile uint32_t g_curr_tick;
volatile uint32_t g_curr_tick_p;

/*Delay in seconds*/
void delay(uint32_t delay){
	uint32_t tickstart = get_tick();
	uint32_t wait = delay;

	if(wait < MAX_DELAY){
		wait += (uint32_t)TICK_FREQ;
	}
	while((get_tick() - tickstart) < wait){}
}

uint32_t get_tick(void){
	__disable_irq();
	g_curr_tick_p = g_curr_tick;
	__enable_irq();
	return g_curr_tick_p;
}

void tick_increment(void){
	g_curr_tick += TICK_FREQ;
}

void timebase_init(void){
	/*Disable global Interrupt*/
	__disable_irq();
	/*Load the timer with number of clock cycles per second*/
	SysTick->LOAD = ONE_SEC_LOAD - 1;
	/*Clear systick current value register*/
	SysTick->VAL = 0;
	/*Select internal clock source*/
	SysTick->CTRL = CTRL_CLKSRC;
	/*Enable Interrupt*/
	SysTick->CTRL |= CTRL_TICKINT;
	/*Enable systick*/
	SysTick->CTRL |= CTRL_ENABLE;
	/*Enable global Interrupt*/
	__enable_irq();
}

void SysTick_Handler(void){
	tick_increment();
}
