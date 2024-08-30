#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_utils.h" 
#include "custom_types.h"

void AES_CBC_Encrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (!inFile || !outFile) {
        perror("File opening failed");
        return;
    }

    u8 buffer[16], ciphertext[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, inFile)) > 0) {
        // Padding (PKCS#7) for the last block if it's smaller than 16 bytes
        if (bytesRead < 16) {
            for (size_t i = bytesRead; i < 16; i++) {
                buffer[i] = 16 - bytesRead;
            }
        }

        // XOR the buffer with the IV
        for (int j = 0; j < 16; j++) {
            buffer[j] ^= iv[j];
        }

        // Encrypt the buffer
        cipher(buffer, key, ciphertext);

        // Write the encrypted block to the output file
        fwrite(ciphertext, 1, 16, outFile);

        // Update IV to the ciphertext block
        memcpy(iv, ciphertext, 16);
    }

    // Add PKCS#7 padding if the file size is a multiple of 16 bytes
    if (bytesRead == 16) {
        memset(buffer, 16, 16); // Add an extra block of padding
        for (int j = 0; j < 16; j++) {
            buffer[j] ^= iv[j];
        }
        cipher(buffer, key, ciphertext);
        fwrite(ciphertext, 1, 16, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}

void AES_CBC_Decrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (!inFile || !outFile) {
        perror("File opening failed");
        return;
    }

    u8 buffer[16], plaintext[16], previousBlock[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, inFile)) > 0) {
        // Save the current ciphertext block for the next IV
        memcpy(previousBlock, buffer, 16);

        AES_decrypt(buffer, key, plaintext);

        // XOR the decrypted block with the IV
        for (int j = 0; j < 16; j++) {
            plaintext[j] ^= iv[j];
        }

        // Update IV to the current ciphertext block
        memcpy(iv, previousBlock, 16);

        // If this is the last block, handle padding removal
        if (feof(inFile)) {
            int padding_len = plaintext[15];
            if (padding_len > 0 && padding_len <= 16) {
                fwrite(plaintext, 1, 16 - padding_len, outFile);
            } else {
                fwrite(plaintext, 1, 16, outFile);
            }
        } else {
            fwrite(plaintext, 1, 16, outFile);
        }
    }

    fclose(inFile);
    fclose(outFile);
}
