#include "aes_cbc.h" // Include the header where the AES_CBC_Encrypt_File and AES_CBC_Decrypt_File functions are declared


int main() {
    const char *inputFile = "modes.pdf"; // Replace with your input file
    const char *encryptedFile = "encrypted_cbc.pdf";
    const char *decryptedFile = "decrypted_cbc.pdf";

    // Example 128-bit (16 bytes) key
    u8 key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x44, 0x4a, 0x54, 0x6d, 0x32, 0x66};
    
    // Example Initialization Vector (IV) - should be random for real applications
    u8 iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // Encrypt the file
    AES_CBC_Encrypt_File(inputFile, encryptedFile, key, iv);

    printf("File encrypted successfully: %s\n", encryptedFile);

     // Reset the IV to the same value as used in encryption
    u8 iv_reset[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    memcpy(iv, iv_reset, 16); // Reset IV for decryption
    
    // Decrypt the file
    AES_CBC_Decrypt_File(encryptedFile, decryptedFile, key, iv);

    printf("File decrypted successfully: %s\n", decryptedFile);

    return 0;
}
