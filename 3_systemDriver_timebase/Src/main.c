#include "main.h"

/*Define*/
#define GPIOAEN		(1U<<0)
#define LEDPIN5		5

/*Variables*/

/*Functions*/
void clock(uint16_t gpio);
void toggle_led(uint16_t pin, uint8_t state);

/*Module:
 * FPU
 * UART
 * GPIO (BSP)
 * TIMEBASE
 */

int main(){
	fpu_enable();
	debug_uart_init();
	timebase_init();
	while(1){
		printf("hello\r\n");
//		toggle_led(LEDPIN5,1);
		delay(1);
	}
}












void clock(uint16_t gpio){
	RCC->AHB1ENR |= gpio;
}
void toggle_led(uint16_t pin, uint8_t state){
	while(1){
		GPIOA->MODER |=  (1U<<(pin*2));
		GPIOA->MODER &=~ (1U<<((pin*2)+1));

		GPIOA->ODR ^= (1U<<pin);

	}
}
