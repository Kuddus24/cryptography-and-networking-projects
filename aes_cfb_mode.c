#include "aes_cfb.h"

int main() {
    u8 key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x44, 0x4a, 0x54, 0x6d, 0x32, 0x66};
    u8 iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    AES_CFB_Encrypt_File("modes.pdf", "encrypted_efb.pdf", key, iv);
    
    
   // Reset the IV to the same value as used in encryption
    u8 iv_reset[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    memcpy(iv, iv_reset, 16);
    
    AES_CFB_Decrypt_File("encrypted_efb.pdf", "decrypted_efb.pdf", key, iv);

    return 0;
}
