/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CAN_HandleTypeDef hcan1;

UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

RNG_STATETypedef rng;

char buff[1200];

uint32_t start = 0, end = 0, totaltime = 0;
extern char decrypted[length_rsa];

CAN_RxHeaderTypeDef canRx;
CAN_TxHeaderTypeDef canTx;

uint32_t mailbox = 0;

uint8_t rxData[8] = {0};
uint8_t txData[8] = {0};

bool handShake = false;
bool ivRecieved = false;
bool sizeRecieved = false;
bool EncDataRec = false;

uint8_t key128[16] = {0};
uint8_t key192[24] = {0};
uint8_t key256[32] = {0};
uint8_t itr = 0;
uint8_t itrrr = 0;

uint8_t aes128IV[16] = {0};

uint8_t masterKey128[16] = {
		0x2b, 0x7e, 0x15, 0x16,
	    0x28, 0xae, 0xd2, 0xa6,
	    0xab, 0xf7, 0x15, 0x88,
	    0x09, 0xcf, 0x4f, 0x3c
};

uint16_t aesDataSize = 0;


uint8_t Encrypted128Data[64];

uint8_t Decrypted128Data[180] = {0};

size_t CBCDecryptData128Size = 0;

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_CAN1_Init(void);
static void MX_USART2_UART_Init(void);
/* USER CODE BEGIN PFP */

void CANTransmit(CAN_TxHeaderTypeDef* tx, uint8_t* data);

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

void CANACKHandshake(){

	canTx.IDE = CAN_ID_EXT;
	canTx.ExtId = 0x01; // For Handshake !
	canTx.DLC = 8;

	for(uint8_t i = 0; i < 8; i++)	txData[i] = 0x01;

	CANTransmit(&canTx, txData);

	handShake = false;

}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */

  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */

  MX_GPIO_Init();
  MX_CAN1_Init();
  MX_USART2_UART_Init();

  /* USER CODE BEGIN 2 */
  filter_config();

//  RNGSeed(&rng, 0, 0, 0, 0);
//  RNGByte(&rng, key128, sizeof(key128));
//
//  for(uint32_t i = 0; i < sizeof(key128); i++ ){
//	  sprintf(buff, "Key op 128 -> 0x%02X \r\n", key128[i]);
//	  HAL_UART_Transmit(&huart2, (uint8_t *)buff, strlen(buff), HAL_MAX_DELAY);
//  }

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {

	if(handShake == true)	CANACKHandshake();

	if(ivRecieved == true && sizeRecieved == true && EncDataRec == true){

		if(AES128_Decrypt(AES_CBC_DEC, Encrypted128Data, sizeof(Encrypted128Data), masterKey128, aes128IV, Decrypted128Data, &CBCDecryptData128Size) != success)    printf("\nAES128 CBC Cipher Decrypt Failed\n");
	    else    printf("\nAES128 CBC Cipher Decrypt Success\n");

	    outputprint(CBCDecryptData128Size, Decrypted128Data);

	}

	/* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */

  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 180;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 2;
  RCC_OscInitStruct.PLL.PLLR = 2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Activate the Over-Drive mode
  */
  if (HAL_PWREx_EnableOverDrive() != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief CAN1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_CAN1_Init(void)
{

  /* USER CODE BEGIN CAN1_Init 0 */

  /* USER CODE END CAN1_Init 0 */

  /* USER CODE BEGIN CAN1_Init 1 */

  /* USER CODE END CAN1_Init 1 */
  hcan1.Instance = CAN1;
  hcan1.Init.Prescaler = 5;
  hcan1.Init.Mode = CAN_MODE_NORMAL;
  hcan1.Init.SyncJumpWidth = CAN_SJW_1TQ;
  hcan1.Init.TimeSeg1 = CAN_BS1_15TQ;
  hcan1.Init.TimeSeg2 = CAN_BS2_2TQ;
  hcan1.Init.TimeTriggeredMode = DISABLE;
  hcan1.Init.AutoBusOff = DISABLE;
  hcan1.Init.AutoWakeUp = DISABLE;
  hcan1.Init.AutoRetransmission = DISABLE;
  hcan1.Init.ReceiveFifoLocked = DISABLE;
  hcan1.Init.TransmitFifoPriority = DISABLE;
  if (HAL_CAN_Init(&hcan1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN CAN1_Init 2 */

  /* USER CODE END CAN1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

void CANTransmit(CAN_TxHeaderTypeDef* tx, uint8_t* data){


	if(HAL_CAN_AddTxMessage(&hcan1, tx, data, &mailbox) != HAL_OK){
		Error_Handler();
	}

}

void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan){

	if(HAL_CAN_GetRxMessage(&hcan1, CAN_RX_FIFO0, &canRx, rxData) != HAL_OK){
		Error_Handler();
	}

	if(canRx.ExtId == 0x10){
		handShake = true;
	}

	if(canRx.ExtId == 0x11 || canRx.ExtId == 0x12){

		for(uint8_t i = 0; i < 8; i++)  aes128IV[itr++] = rxData[i];

		if(canRx.ExtId == 0x12){
			ivRecieved = true;
		}

	}

	if(canRx.ExtId == 0x13){
		aesDataSize = ((uint16_t)rxData[0] << 8 | rxData[1]);
		sizeRecieved = true;
	}

	if(canRx.ExtId == 0x14 || canRx.ExtId == 0x15 || canRx.ExtId == 0x16 || canRx.ExtId == 0x17
	|| canRx.ExtId == 0x18 || canRx.ExtId == 0x19 || canRx.ExtId == 0x1A || canRx.ExtId == 0x1B ){

		for(uint8_t i = 0; i < 8; i++){
			Encrypted128Data[itrrr++] = rxData[i];
		}
		if(canRx.ExtId == 0x1B)	EncDataRec = true;
	}

}
/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}

#ifdef  USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
