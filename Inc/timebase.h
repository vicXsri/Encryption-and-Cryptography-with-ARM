/*
 * timebase.h
 *
 *  Created on: Apr 9, 2025
 *      Author: Vichu
 */

#ifndef TIMEBASE_H_
#define TIMEBASE_H_

#include "main.h"

/*Private Defines*/
#define CTRL_ENABLE		(1U << 0)
#define CTRL_TICKINT	(1U << 1)
#define CTRL_CLKSRC		(1U << 2)
#define CTRL_COUNTFLAG	(1U << 16)

#define	ONE_SEC_LOAD	16000000
#define MAX_DELAY		0XFFFFFFFF
#define TICK_FREQ	1

/*Private Variables*/


/*Private Functions*/
void timebase_init(void);
void tick_increment(void);
uint32_t get_tick(void);
#endif /* TIMEBASE_H_ */
