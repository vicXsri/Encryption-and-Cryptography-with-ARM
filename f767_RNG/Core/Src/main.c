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

#include "implementation.h"

/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define	key128_BlockSize	4
#define	key192_BlockSize	6
#define	key256_BlockSize	8
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
CAN_HandleTypeDef hcan1;

RNG_HandleTypeDef hrng;

UART_HandleTypeDef huart3;

/* USER CODE BEGIN PV */
char buff[500];

uint32_t rngData = 0;

uint8_t key128[16] = {0};
uint8_t key192[24] = {0};
uint8_t key256[32] = {0};

uint32_t tempkey[8] = {0};

uint32_t start = 0, end = 0, totaltime = 0;

CAN_RxHeaderTypeDef canRx;
CAN_TxHeaderTypeDef canTx;

uint32_t mailbox = 0;

uint8_t rxData[8] = {0};
uint8_t txData[8] = {0};

extern uint8_t IV[];

uint8_t masterKey128[16] = {
		0x2b, 0x7e, 0x15, 0x16,
	    0x28, 0xae, 0xd2, 0xa6,
	    0xab, 0xf7, 0x15, 0x88,
	    0x09, 0xcf, 0x4f, 0x3c
};

uint8_t fulltext128[] =
{
  0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
  0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
  0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
  0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};

uint8_t CBCEncryptData128[64]={0};

size_t CBCEncryptData128Size=0;
bool ackReady = false;
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART3_UART_Init(void);
static void MX_RNG_Init(void);
static void MX_CAN1_Init(void);
/* USER CODE BEGIN PFP */

void CANTransmit(CAN_TxHeaderTypeDef* tx, uint8_t* data);

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */
void keyGenerator(uint8_t keyBlockSize, uint8_t* key){

	for(uint8_t i = 0; i < keyBlockSize; i++)	tempkey[i] = HAL_RNG_GetRandomNumber(&hrng);

	for(uint8_t i = 0; i < keyBlockSize; i++){

		key[4 * i + 0 ] = (uint8_t) ((tempkey[i] >> 24 ) & 0xFF);
		key[4 * i + 1 ] = (uint8_t) ((tempkey[i] >> 16 ) & 0xFF);
		key[4 * i + 2 ] = (uint8_t) ((tempkey[i] >> 8  ) & 0xFF);
		key[4 * i + 3 ] = (uint8_t) ( tempkey[i]         & 0xFF);

	}

	for(uint8_t i = 1; i <= keyBlockSize * 4; i++){

		sprintf(buff, "0x%02X ", key[i-1]);
		HAL_UART_Transmit(&huart3, (uint8_t *)buff, strlen(buff), HAL_MAX_DELAY);

		if(i % 4 == 0 ){
			sprintf(buff, "\r\n");
			HAL_UART_Transmit(&huart3, (uint8_t *)buff, strlen(buff), HAL_MAX_DELAY);
		}

	}

}

void printText(char* text){
	  sprintf(buff, "%s", text);
	  HAL_UART_Transmit(&huart3, (uint8_t *)buff, strlen(buff), HAL_MAX_DELAY);
}

void CANHandshake(){

	canTx.IDE = CAN_ID_EXT;
	canTx.ExtId = 0x10; // For Handshake !
	canTx.DLC = 8;

	for(uint8_t i = 0; i < 8; i++)	txData[i] = 0x01;

	CANTransmit(&canTx, txData);
}

void CANSendIV(){

	uint8_t itr = 0;

	canTx.IDE = CAN_ID_EXT;
	canTx.ExtId = 0x11; // 0x11 for iv[0-7], 0x12 for iv[8-15]
	canTx.DLC = 8;

	for(uint8_t i = 0; i < 2; i ++){

		for(uint8_t j = 0; j < 8; j ++) txData[j] = IV[itr++];

		CANTransmit(&canTx, txData);

		canTx.ExtId += 0x01;

	}

}

void CANSendDatasize(){

	uint16_t length = sizeof(fulltext128);

	canTx.IDE = CAN_ID_EXT;
	canTx.ExtId = 0x13;
	canTx.DLC = 8;


	txData[0] = length >> 8;
	txData[1] = length & 0xFF;


	CANTransmit(&canTx, txData);

}

void CanTransmitEncryptedData(){

	uint8_t itr = 0;

	canTx.IDE = CAN_ID_EXT;
	canTx.ExtId = 0x14; //0x14 - 0x1B
	canTx.DLC = 8;

	for(uint8_t i = 0 ; i < 8; i++){

		for(uint8_t j = 0 ; j < 8; j++)	txData[j] = CBCEncryptData128[itr++];

		CANTransmit(&canTx, txData);

		canTx.ExtId++;
	}

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
  MX_USART3_UART_Init();
  MX_RNG_Init();
  MX_CAN1_Init();
  /* USER CODE BEGIN 2 */

  filter_config();
//  printText("Key128 \r\n");
//  keyGenerator(key128_BlockSize, key128);

//  printText("Key192 \r\n");
//  keyGenerator(key192_BlockSize, key192);
//
//  printText("Key256 \r\n");
//  keyGenerator(key256_BlockSize, key256);

  HAL_CAN_Start(&hcan1);

  HAL_CAN_ActivateNotification(&hcan1, CAN_IT_RX_FIFO0_MSG_PENDING);

  CANHandshake();

  while(ackReady != true);

  CANSendIV();

  CANSendDatasize();

  if(AES128_Encrypt(AES_CBC_ENC, fulltext128, sizeof(fulltext128), masterKey128, IV, CBCEncryptData128, &CBCEncryptData128Size) != success)    printf("\nAES128 CBC Cipher Encrypt Failed\n");
  else    printf("\nAES128 CBC Cipher Encrypt Success\n");

  CanTransmitEncryptedData();

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {

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
  RCC_OscInitStruct.PLL.PLLN = 216;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 9;
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

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_7) != HAL_OK)
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
  hcan1.Init.Prescaler = 6;
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
  * @brief RNG Initialization Function
  * @param None
  * @retval None
  */
static void MX_RNG_Init(void)
{

  /* USER CODE BEGIN RNG_Init 0 */

  /* USER CODE END RNG_Init 0 */

  /* USER CODE BEGIN RNG_Init 1 */

  /* USER CODE END RNG_Init 1 */
  hrng.Instance = RNG;
  if (HAL_RNG_Init(&hrng) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN RNG_Init 2 */

  /* USER CODE END RNG_Init 2 */

}

/**
  * @brief USART3 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART3_UART_Init(void)
{

  /* USER CODE BEGIN USART3_Init 0 */

  /* USER CODE END USART3_Init 0 */

  /* USER CODE BEGIN USART3_Init 1 */

  /* USER CODE END USART3_Init 1 */
  huart3.Instance = USART3;
  huart3.Init.BaudRate = 115200;
  huart3.Init.WordLength = UART_WORDLENGTH_8B;
  huart3.Init.StopBits = UART_STOPBITS_1;
  huart3.Init.Parity = UART_PARITY_NONE;
  huart3.Init.Mode = UART_MODE_TX_RX;
  huart3.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart3.Init.OverSampling = UART_OVERSAMPLING_16;
  huart3.Init.OneBitSampling = UART_ONE_BIT_SAMPLE_DISABLE;
  huart3.AdvancedInit.AdvFeatureInit = UART_ADVFEATURE_NO_INIT;
  if (HAL_UART_Init(&huart3) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART3_Init 2 */

  /* USER CODE END USART3_Init 2 */

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
  __HAL_RCC_GPIOD_CLK_ENABLE();
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

	if(canRx.ExtId == 0x01){
		ackReady = true;
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
