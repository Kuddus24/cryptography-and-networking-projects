#include "custom_types.h"
#include "modes.h"

void printMenu() {
    printf("Choose an operation:\n");
    printf("1. AES-128 CBC Encrypt File\n");
    printf("2. AES-128 CBC Decrypt File\n");
    printf("3. AES-128 CFB Encrypt File\n");
    printf("4. AES-128 CFB Decrypt File\n");
    printf("5. AES-128 CTR Encrypt File\n");
    printf("6. AES-128 CTR Decrypt File\n");
    printf("7. AES-128 ECB Encrypt File\n");
    printf("8. AES-128 ECB Decrypt File\n");
    printf("9. AES-128 OFB Encrypt File\n");
    printf("10. AES-128 OFB Decrypt File\n");
    printf("11. Exit\n");
}

void getInputData(char *file, u8 *key, u8 *iv_or_nonce) {
    printf("Enter file path: ");
    scanf("%255s", file);

    printf("Enter 128-bit key (16 hex values separated by spaces):\n");
    for (int i = 0; i < 16; i++) {
        scanf("%2hhx", &key[i]);
    }

    printf("Enter IV/Nonce (16 hex values separated by spaces):\n");
    for (int i = 0; i < 16; i++) {
        scanf("%2hhx", &iv_or_nonce[i]);
    }
}

int main() {
    int choice;
    char inputFile[256], outputFile[256];
    u8 key[16], iv_or_nonce[16];

    while (1) {
        printMenu();
        printf("Enter your choice: ");
        scanf("%d", &choice);
        
        switch (choice) {
            case 1: {  // CBC Encrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for encryption: ");
                scanf("%s", outputFile);
                
                clock_t start_cbc_enc = clock();
                AES_CBC_Encrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_cbc_enc = clock();
                
                printf("File encrypted successfully to %s\n", outputFile);
                printf("Encryption time: %f seconds\n", (double)(end_cbc_enc - start_cbc_enc) / CLOCKS_PER_SEC);
                break;
            }
            
            case 2: {  // CBC Decrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for decryption: ");
                scanf("%s", outputFile);
                
                clock_t start_cbc_dec = clock();
                AES_CBC_Decrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_cbc_dec = clock();
                
                printf("File decrypted successfully to %s\n", outputFile);
                printf("Decryption time: %f seconds\n", (double)(end_cbc_dec - start_cbc_dec) / CLOCKS_PER_SEC);
                break;
            }

            case 3: {  // CFB Encrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for encryption: ");
                scanf("%s", outputFile);
                
                clock_t start_cfb_enc = clock();
                AES_CFB_Encrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_cfb_enc = clock();
                
                printf("File encrypted successfully to %s\n", outputFile);
                printf("Encryption time: %f seconds\n", (double)(end_cfb_enc - start_cfb_enc) / CLOCKS_PER_SEC);
                break;
            }

            case 4: {  // CFB Decrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for decryption: ");
                scanf("%s", outputFile);
                
                clock_t start_cfb_dec = clock();
                AES_CFB_Decrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_cfb_dec = clock();
                
                printf("File decrypted successfully to %s\n", outputFile);
                printf("Decryption time: %f seconds\n", (double)(end_cfb_dec - start_cfb_dec) / CLOCKS_PER_SEC);
                break;
            }

            case 5: {  // CTR Encrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for encryption: ");
                scanf("%s", outputFile);
                
                clock_t start_ctr_enc = clock();
                AES_CTR_Encrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_ctr_enc = clock();
                
                printf("File encrypted successfully to %s\n", outputFile);
                printf("Encryption time: %f seconds\n", (double)(end_ctr_enc - start_ctr_enc) / CLOCKS_PER_SEC);
                break;
            }

            case 6: {  // CTR Decrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for decryption: ");
                scanf("%s", outputFile);
                
                clock_t start_ctr_dec = clock();
                AES_CTR_Decrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_ctr_dec = clock();
                
                printf("File decrypted successfully to %s\n", outputFile);
                printf("Decryption time: %f seconds\n", (double)(end_ctr_dec - start_ctr_dec) / CLOCKS_PER_SEC);
                break;
            }

            case 7: {  // ECB Encrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for encryption: ");
                scanf("%s", outputFile);
                
                clock_t start_ecb_enc = clock();
                AES_ECB_Encrypt_File(inputFile, outputFile, key);
                clock_t end_ecb_enc = clock();
                
                printf("File encrypted successfully to %s\n", outputFile);
                printf("Encryption time: %f seconds\n", (double)(end_ecb_enc - start_ecb_enc) / CLOCKS_PER_SEC);
                break;
            }

            case 8: {  // ECB Decrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for decryption: ");
                scanf("%s", outputFile);
                
                clock_t start_ecb_dec = clock();
                AES_ECB_Decrypt_File(inputFile, outputFile, key);
                clock_t end_ecb_dec = clock();
                
                printf("File decrypted successfully to %s\n", outputFile);
                printf("Decryption time: %f seconds\n", (double)(end_ecb_dec - start_ecb_dec) / CLOCKS_PER_SEC);
                break;
            }

            case 9: {  // OFB Encrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for encryption: ");
                scanf("%s", outputFile);
                
                clock_t start_ofb_enc = clock();
                AES_OFB_Encrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_ofb_enc = clock();
                
                printf("File encrypted successfully to %s\n", outputFile);
                printf("Encryption time: %f seconds\n", (double)(end_ofb_enc - start_ofb_enc) / CLOCKS_PER_SEC);
                break;
            }

            case 10: { // OFB Decrypt
                getInputData(inputFile, key, iv_or_nonce);
                printf("Enter output file path for decryption: ");
                scanf("%s", outputFile);
                
                clock_t start_ofb_dec = clock();
                AES_OFB_Decrypt_File(inputFile, outputFile, key, iv_or_nonce);
                clock_t end_ofb_dec = clock();
                
                printf("File decrypted successfully to %s\n", outputFile);
                printf("Decryption time: %f seconds\n", (double)(end_ofb_dec - start_ofb_dec) / CLOCKS_PER_SEC);
                break;
            }

            case 11: // Exit
                printf("Exiting...\n");
                exit(0);
            
            default:
                printf("Invalid choice, please try again.\n");
        }
    }

    return 0;
}
