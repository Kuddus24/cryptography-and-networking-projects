# Cryptography and Networking Projects

This repository contains various cryptographic and networking projects, including:

- **AES Implementation:** A complete implementation of the Advanced Encryption Standard (AES) in C.
- **Multi-threaded Socket Programming with OpenSSL:** Examples of secure communication using OpenSSL in multi-threaded socket applications.
- **Huffman Encoding:** An efficient implementation of Huffman encoding for data compression.

## Features

### AES Implementation
- Key expansion, encryption, and decryption processes.
- Detailed comments and documentation.

### Multi-threaded Socket Programming
- Concurrent server and client applications.
- Secure communication using OpenSSL.

### Huffman Encoding
- Encoding and decoding processes.
- Optimized for handling large datasets.

## Installation

To set up this project locally:

1. **Clone the repository:**

    ```bash
    git clone https://github.com/kuddus24/cryptography-and-networking-project.git
    ```

2. **Navigate to the project directory:**

    ```bash
    cd cryptography-and-networking-project
    ```

3. **Follow additional setup instructions provided in the specific project directories.**

## Usage

### AES Implementation

1. **Compile the code:**

    ```bash
    gcc -o aes aes.c
    ```

2. **Run the application:**

    ```bash
    ./aes
    ```

### Multi-threaded Socket Programming

1. **Compile the server and client programs:**

    ```bash
    gcc -o server server.c -lssl -lcrypto
    gcc -o client client.c -lssl -lcrypto
    ```

2. **Run the server and client applications:**

    ```bash
    ./server
    ./client
    ```

### Huffman Encoding

1. **Compile the Huffman encoding code:**

    ```bash
    gcc -o huffman huffman.c
    ```

2. **Run the application:**

    ```bash
    ./huffman
    ```




