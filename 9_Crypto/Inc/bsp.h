/*
 * bsp.h
 *
 *  Created on: Apr 13, 2025
 *      Author: Vichu
 */

#ifndef BSP_H_
#define BSP_H_
/*Private Includes*/
#include "main.h"

/*Private Defines*/
#define GPIOAEN		(1U << 0)
#define GPIOCEN		(1U << 2)
#define PIN5		(1U << 5)
#define LEDPIN		PIN5
#define PIN13		(1U << 13)
#define BTNPIN		PIN13

/*Private Functions*/
void led_init(void);
void led_on(void);
void led_off(void);
void button_init(void);
bool get_btn_state(void);
/*Private Variables*/

#endif /* BSP_H_ */
