#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_utils.h" 
#include "custom_types.h"


void AES_OFB_Encrypt(u8* input, const u8* key, u8* output, u8* iv, int length) {
    u8 buffer[16];
    for (int i = 0; i < length; i += 16) {
        // Encrypt the IV
        cipher(iv, key, buffer);
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                output[i + j] = input[i + j] ^ buffer[j];
            }
        }
        // Update IV for the next block
        // Note: In OFB mode, IV is incremented or modified here for each block
        // For simplicity, we'll just keep it constant
        memcpy(iv, buffer, 16);
    }
}

void AES_OFB_Decrypt(u8* input, const u8* key, u8* output, u8* iv, int length) {
    u8 buffer[16];
    for (int i = 0; i < length; i += 16) {
        // Encrypt the IV
        cipher(iv, key, buffer);
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                output[i + j] = input[i + j] ^ buffer[j];
            }
        }
        // Update IV for the next block
        memcpy(iv, buffer, 16);
    }
}

void AES_OFB_Encrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (!inFile || !outFile) {
        perror("File opening failed");
        return;
    }

    u8 buffer[16], ciphertext[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, inFile)) > 0) {
        // Encrypt the block
        AES_OFB_Encrypt(buffer, key, ciphertext, iv, bytesRead);
        fwrite(ciphertext, 1, bytesRead, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

void AES_OFB_Decrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (!inFile || !outFile) {
        perror("File opening failed");
        return;
    }

    u8 buffer[16], plaintext[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, inFile)) > 0) {
        // Decrypt the block
        AES_OFB_Decrypt(buffer, key, plaintext, iv, bytesRead);
        fwrite(plaintext, 1, bytesRead, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

