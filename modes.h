#ifndef MODES_H
#define MODES_H

#include "aes_utils.h"


#endif // MODES_H
//CBC mode;
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


//CFB mode;

void AES_CFB_Encrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (!inFile || !outFile) {
        perror("File opening failed");
        return;
    }

    u8 buffer[16], ciphertext[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, inFile)) > 0) {
        u8 tempIV[16];
        memcpy(tempIV, iv, 16);  // Preserve IV for encryption

        cipher(iv, key, ciphertext);

        for (size_t j = 0; j < bytesRead; j++) {
            ciphertext[j] = buffer[j] ^ ciphertext[j];
            iv[j] = ciphertext[j];  // Shift the IV
        }

        fwrite(ciphertext, 1, bytesRead, outFile);

        // If the last chunk is not a full block, handle it here
        if (bytesRead < 16) {
            break;
        }
    }

    fclose(inFile);
    fclose(outFile);
}


void AES_CFB_Decrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* iv) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (!inFile || !outFile) {
        perror("File opening failed");
        return;
    }

    u8 buffer[16], plaintext[16];
    size_t bytesRead;

    while ((bytesRead = fread(buffer, 1, 16, inFile)) > 0) {
        u8 tempIV[16];
        memcpy(tempIV, iv, 16);  // Preserve IV for decryption

        cipher(iv, key, plaintext);

        for (size_t j = 0; j < bytesRead; j++) {
            plaintext[j] = buffer[j] ^ plaintext[j];
            iv[j] = buffer[j];  // Shift the IV
        }

        fwrite(plaintext, 1, bytesRead, outFile);

        // If the last chunk is not a full block, handle it here
        if (bytesRead < 16) {
            break;
        }
    }

    fclose(inFile);
    fclose(outFile);
}


//CTR mode;

// Function to increment the 128-bit counter
void incrementCounter(u8* counter) {
    for (int i = 15; i >= 0; i--) {
        if (++counter[i]) break;
    }
}

// AES CTR Encryption
void AES_CTR_Encrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* nonce) {
    FILE *inFile = fopen(inputFile, "rb");
    FILE *outFile = fopen(outputFile, "wb");

    if (!inFile || !outFile) {
        perror("File opening failed");
        return;
    }

    u8 buffer[16], counter[16];
    size_t bytesRead;

    // Initialize the counter with the nonce
    memcpy(counter, nonce, 16);

    while ((bytesRead = fread(buffer, 1, 16, inFile)) > 0) {
        u8 encryptedCounter[16];
        cipher(counter, key, encryptedCounter); // Encrypt the counter

        // XOR the encrypted counter with the buffer (plaintext) to produce ciphertext
        for (size_t i = 0; i < bytesRead; i++) {
            buffer[i] ^= encryptedCounter[i];
        }

        // Write the ciphertext to the output file
        fwrite(buffer, 1, bytesRead, outFile);

        // Increment the counter
        incrementCounter(counter);
    }

    fclose(inFile);
    fclose(outFile);
}

// AES CTR Decryption (same as encryption)
void AES_CTR_Decrypt_File(const char* inputFile, const char* outputFile, const u8* key, u8* nonce) {
    // Decryption is identical to encryption in CTR mode
    AES_CTR_Encrypt_File(inputFile, outputFile, key, nonce);
}

//ECB mode;

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

//OFB mode;

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

