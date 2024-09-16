#include "aes_utils.h"
#include "custom_types.h"



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
