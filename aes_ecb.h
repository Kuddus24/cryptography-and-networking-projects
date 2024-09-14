#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes_utils.h" 
#include "custom_types.h"

void AES_ECB_Encrypt_File(const char* inputFile, const char* outputFile, const u8* key) {
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

        // Encrypt the buffer
        cipher(buffer, key, ciphertext);

        // Write the encrypted block to the output file
        fwrite(ciphertext, 1, 16, outFile);
    }

    // Add PKCS#7 padding if the file size is a multiple of 16 bytes
    if (bytesRead == 16) {
        memset(buffer, 16, 16); // Add an extra block of padding
        cipher(buffer, key, ciphertext);
        fwrite(ciphertext, 1, 16, outFile);
    }

    fclose(inFile);
    fclose(outFile);
}


void AES_ECB_Decrypt_File(const char* inputFile, const char* outputFile, const u8* key) {
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
        AES_decrypt(buffer, key, plaintext);

        // Check if this is the last block by looking at the next block
        size_t nextRead = fread(buffer, 1, 16, inFile);

        if (nextRead == 0 && feof(inFile)) {
            // This is the last block, handle padding removal
            int padding_len = plaintext[15];

            // Check for valid padding (1 to 16 bytes)
            if (padding_len > 0 && padding_len <= 16) {
                // Ensure padding bytes are all the same (PKCS#7 standard)
                int valid_padding = 1;
                for (int i = 16 - padding_len; i < 16; i++) {
                    if (plaintext[i] != padding_len) {
                        valid_padding = 0;
                        break;
                    }
                }
                // If valid padding, write the unpadded data
                if (valid_padding) {
                    fwrite(plaintext, 1, 16 - padding_len, outFile);
                } else {
                    // If padding is invalid, write the whole block as-is
                    fwrite(plaintext, 1, 16, outFile);
                }
            } else {
                // If padding is invalid or not present, write the full block
                fwrite(plaintext, 1, 16, outFile);
            }
        } else {
            // If not the last block, just write the decrypted data
            fwrite(plaintext, 1, 16, outFile);
        }

        // Reset file pointer if we pre-read the next block
        if (nextRead > 0) {
            fseek(inFile, -nextRead, SEEK_CUR);
        }
    }

    fclose(inFile);
    fclose(outFile);
}
