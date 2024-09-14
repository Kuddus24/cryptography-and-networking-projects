#include"aes_ecb.h"

int main() {
    
    u8 key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // Encrypt and decrypt a file
    AES_ECB_Encrypt_File("input.txt", "encrypted_ecb.pdf", key);
    AES_ECB_Decrypt_File("encrypted_ecb.pdf", "decrypted_ecb.pdf", key);

    return 0;
}
