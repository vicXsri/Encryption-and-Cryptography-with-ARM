# Encryption-and-Cryptography-with-ARM

# Cryptography on ARM (STM32F446RE)

This repository contains C implementations of classical and modern cryptographic algorithms, built and tested on the STM32F446RE Nucleo board. It includes a small custom cryptography library, example programs, and a PDF that documents the approach, implementations, and outputs captured from hardware runs.

## Contents

### Algorithms Implemented
- Monoalphabetic cipher  
- Polyalphabetic cipher (Vigenère‑style approach)  
- AES (key schedule, encryption, and implemented modes)

### Library
- Minimal C library for the above algorithms  
- Reusable headers and source files  

### Targets
- STM32F446RE (ARM Cortex‑M4)  
- Example projects for on‑device testing  

### Documentation
- PDF with explanations, code walkthroughs, and output logs/screenshots from the MCU  

## Project Goals
- Translate cryptographic concepts into working embedded implementations.  
- Validate algorithms on real hardware using deterministic test vectors and observed outputs.  
- Provide a clean baseline for future work on public‑key cryptography and secure random generation methods for embedded systems.

```mermaid
flowchart TD
    A[Power On] --> B[Initialize CAN]
    B --> C[Load Shared AES Key]
    C --> D[Select AES Mode<br/>ECB / CBC / CFB / OFB / CTR]

    D --> E{Which Mode?}

    E --> ECB1[ECB:<br/>No IV needed]
    E --> CBC1[CBC:<br/>Generate or load IV]
    E --> CFB1[CFB:<br/>Generate or load IV]
    E --> OFB1[OFB:<br/>Generate or load IV]
    E --> CTR1[CTR:<br/>Generate nonce/counter]

    ECB1 --> TX0[Prepare Plaintext]
    CBC1 --> TX0
    CFB1 --> TX0
    OFB1 --> TX0
    CTR1 --> TX0

    TX0 --> TX1[Pad if needed<br/>ECB/CBC only]
    TX1 --> TX2[Encrypt Plaintext]
    TX2 --> TX3[Build CAN Packet:<br/>Mode + IV/Nonce if needed + Ciphertext]
    TX3 --> TX4[Send on CAN Bus]

    TX4 --> RX0[Receive CAN Packet]
    RX0 --> RX1[Read Mode]
    RX1 --> RX2[Read IV / Nonce / Counter if present]
    RX2 --> RX3[Decrypt Ciphertext]
    RX3 --> RX4[Remove Padding<br/>ECB/CBC only]
    RX4 --> RX5[Recovered Plaintext]

```