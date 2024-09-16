#include "aes_utils.h" 
#include "custom_types.h"

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
