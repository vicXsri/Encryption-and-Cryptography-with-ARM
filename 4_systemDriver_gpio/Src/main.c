#include "main.h"


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
	button_init();
	led_init();
	while(1){
//		printf("hello\r\n");
//		delay(1);
		(get_btn_state())? led_on(): led_off();
	}
}
