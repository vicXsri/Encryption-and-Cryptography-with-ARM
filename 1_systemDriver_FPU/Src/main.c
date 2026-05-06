#include "main.h"


#define GPIOAEN		(1U<<0)
#define LEDPIN5		5
#define	delay 		1600000

void toggle_led(uint16_t pin);
void clock(uint16_t gpio);

/*Module:
 * FPU
 * UART
 * GPIO
 * TIMEBASE
 */

int main(){
	while(1){
		fpu_enable();

		clock(GPIOAEN);
		toggle_led(LEDPIN5);
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

		for(int i=0;i< delay;i++){}
	}
}
