#include "stm32f4xx.h"
#include "fpu.h"

void fpu_enable(void){
	/*enable FPU : Enbale CP10 & CP11 to full access*/
	SCB->CPACR |= (1U<<20);
	SCB->CPACR |= (1U<<21);
	SCB->CPACR |= (1U<<22);
	SCB->CPACR |= (1U<<23);
}
