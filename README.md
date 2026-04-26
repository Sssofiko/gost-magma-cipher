# GOST Magma Cipher

Python implementation of the **Magma block cipher** and several encryption modes according to Russian cryptographic standards:

- **GOST R 34.12-2015** — Magma block cipher
- **GOST R 34.13-2015** — block cipher modes of operation

The project includes the implementation of the base Magma algorithm, encryption/decryption modes, MAC generation, and unit tests based on known test vectors.

## Features

- Magma block cipher implementation
- Key expansion for 256-bit keys
- Block encryption and decryption
- File encryption and decryption
- Support for several modes of operation:
  - ECB
  - CTR
  - OFB
  - CBC
  - CFB
  - MAC / CMAC-like authentication code
- Command-line interaction for encrypting and decrypting files
- Unit tests for both the base cipher and operation modes
