# Cryptography and Networking Projects

This repository contains various cryptographic and networking projects, including:

- **AES Implementation:** A complete implementation of the Advanced Encryption Standard (AES) in C.


## Features

### AES Implementation
- Key expansion, encryption, and decryption processes.
- Detailed comments and documentation.
- {custom_types.h}
- {aes128_keyExpansion.c}
- {aes128_encryption.c}

### AES Modes of Operation
- **Files:**
  - **`aes_cbc.h`** & **`aes_cbc_mode.c`**: Implements AES in Cipher Block Chaining (CBC) mode, which adds an initialization vector to enhance security.
  - **`aes_cfb.h`** & **`aes_cfb_mode.c`**: Implements AES in Cipher Feedback (CFB) mode, enabling encryption of varying sizes of plaintext.
  - **`aes_ctr.h`** & **`aes_ctr_mode.c`**: Implements AES in Counter (CTR) mode, allowing for parallel processing of data blocks.
  - **`aes_ofb.h`** & **`aes_ofb_mode.c`**: Implements AES in Output Feedback (OFB) mode, converting block ciphers into stream ciphers.












