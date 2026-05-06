#include "main.h"

/*Define*/
#define GPIOAEN		(1U<<0)
#define LEDPIN5		5
#define	delay 		100000

/*Variables*/

/*Functions*/
void toggle_led(uint16_t pin);
void clock(uint16_t gpio);

/*Module:
 * FPU
 * UART
 * GPIO
 * TIMEBASE
 */

int main(){
	fpu_enable();
	debug_uart_init();
	while(1){
		printf("hello\r\n");
		for(int i=0;i< delay;i++);
//		toggle_led(LEDPIN5);
	}
}












void clock(uint16_t gpio){
	RCC->AHB1ENR |= gpio;
}
void toggle_led(uint16_t pin){
	while(1){
		GPIOA->MODER |=  (1U<<(pin*2));
		GPIOA->MODER &=~ (1U<<((pin*2)+1));

		GPIOA->ODR ^= (1U<<pin);

//		for(int i=0;i< delay;i++){}
	}
}
