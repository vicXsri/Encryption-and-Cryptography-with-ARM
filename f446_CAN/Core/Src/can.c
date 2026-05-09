/*
 * can.c
 *
 *  Created on: Jan 15, 2024
 *      Author: work
 */

#include "main.h"



extern UART_HandleTypeDef huart2;

char bu[500];
void filter_config(void){
	CAN_FilterTypeDef CanFilter;
	CanFilter.FilterActivation = ENABLE;
	CanFilter.FilterBank = 0;
	CanFilter.FilterFIFOAssignment = CAN_RX_FIFO0;
	CanFilter.FilterIdHigh = 0x0000;
	CanFilter.FilterIdLow = 0x0000;
	CanFilter.FilterMaskIdHigh = 0x0000;
	CanFilter.FilterMaskIdLow = 0x0000;
	CanFilter.FilterMode = CAN_FILTERMODE_IDMASK;
	CanFilter.FilterScale = CAN_FILTERSCALE_32BIT;
	CanFilter.SlaveStartFilterBank =14;
	  sprintf(bu, "check error : %d\r\n",HAL_CAN_ConfigFilter(&hcan1, &CanFilter));
	  HAL_UART_Transmit(&huart2, (uint8_t*)bu, strlen(bu), HAL_MAX_DELAY);
//	if(HAL_CAN_ConfigFilter(&hcan1, &CanFilter) != HAL_OK){
//		Error_Handler();
//	}
}

