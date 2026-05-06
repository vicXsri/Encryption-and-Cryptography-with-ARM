#include "main.h"


/*Module:
 * FPU
 * UART
 * GPIO (BSP)
 * TIMEBASE
uint8_t key = 3;
uint8_t length = 5;
 */

uint32_t start = 0, end = 0, totaltime = 0;

int main(){

	fpu_enable();

	debug_uart_init();

	timebase_init();

	start = get_tick();

     AES128_ECB();

     end = get_tick();

     totaltime = end - start;

     printf("total time => %lu\r\n", totaltime);

//   AES192_ECB();
//   AES256_ECB();
//
//   AES128_CBC();
//   AES192_CBC();
//   AES256_CBC();
//
//	 AES128_CFB();
//	 AES192_CFB();
//   AES256_CFB();
//
//	 AES128_OFB();
//	 AES192_OFB();
//   AES256_OFB();
//
//	 AES128_CTR();
//	 AES192_CTR();
//   AES256_CTR();

//   RSA();

	while(1);

	return 0;
}
