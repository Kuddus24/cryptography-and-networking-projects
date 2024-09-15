//Your code snippet implements the AES-128 key expansion,encryption and decryption  using Intel's AES intrinsics

#include <stdio.h>
#include <wmmintrin.h> // Include the header for AES intrinsics

// Inline function for AES key expansion assistance
inline __m128i AES_128_ASSIST(__m128i temp1, __m128i temp2) {
    __m128i temp3;
    temp2 = _mm_shuffle_epi32(temp2, 0xff); // Shuffle the temp2
    temp3 = _mm_slli_si128(temp1, 0x4); // Shift left by 4 bytes
    temp1 = _mm_xor_si128(temp1, temp3); // XOR
    temp3 = _mm_slli_si128(temp3, 0x4); // Shift left by another 4 bytes
    temp1 = _mm_xor_si128(temp1, temp3); // XOR
    temp3 = _mm_slli_si128(temp3, 0x4); // Shift left by another 4 bytes
    temp1 = _mm_xor_si128(temp1, temp3); // XOR
    temp1 = _mm_xor_si128(temp1, temp2); // XOR with shuffled temp2
    return temp1;
}

// Function to perform AES-128 key expansion
void AES_128_Key_Expansion (const unsigned char *userkey, unsigned char *key)
{
    __m128i temp1, temp2;
    __m128i *Key_Schedule = (__m128i*)key;

    temp1 = _mm_loadu_si128((__m128i*)userkey);
    Key_Schedule[0] = temp1;

    // Round constant values for AES key expansion
    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[1] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[2] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[3] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[4] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[5] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[6] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[7] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[8] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[9] = temp1;

    temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
    temp1 = AES_128_ASSIST(temp1, temp2);
    Key_Schedule[10] = temp1;
}

// Function to print the key schedule
void print_key_schedule(const unsigned char *key_schedule) {
    for (int i = 0; i < 11; i++) { // 10 rounds + initial key
        printf("Round %d: ", i);
        for (int j = 0; j < 16; j++) {
            printf("%02x ", key_schedule[i * 16 + j]);
        }
        printf("\n");
    }
}

// AES ECB Encryption function
void AES_ECB_encrypt(const unsigned char *in, unsigned char *out, unsigned long length, const unsigned char *key, int number_of_rounds) {
    __m128i tmp;
    int i, j;

    // Ensure that the length is a multiple of 16 bytes (AES block size)
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;

    // Loop through each block of plaintext
    for (i = 0; i < length; i++) {
        // Load the next block of plaintext
        tmp = _mm_loadu_si128(&((__m128i*)in)[i]);

        // Initial XOR with the first key (round 0)
        tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);

        // Perform AES encryption rounds
        for (j = 1; j < number_of_rounds; j++) {
            tmp = _mm_aesenc_si128(tmp, ((__m128i*)key)[j]);
        }

        // Perform the final round of encryption
        tmp = _mm_aesenclast_si128(tmp, ((__m128i*)key)[j]);

        // Store the encrypted block in the output
        _mm_storeu_si128(&((__m128i*)out)[i], tmp);
    }
}

// AES ECB Decryption function
void AES_ECB_decrypt(const unsigned char *in, unsigned char *out, unsigned long length, const unsigned char *key, int number_of_rounds) {
    __m128i tmp;
    int i, j;

    // Ensure that the length is a multiple of 16 bytes (AES block size)
    if (length % 16)
        length = length / 16 + 1;
    else
        length = length / 16;

    // Loop through each block of ciphertext
    for (i = 0; i < length; i++) {
        // Load the next block of ciphertext
        tmp = _mm_loadu_si128(&((__m128i*)in)[i]);

        // Initial XOR with the first key (round 0)
        tmp = _mm_xor_si128(tmp, ((__m128i*)key)[0]);

        // Perform AES decryption rounds
        for (j = 1; j < number_of_rounds; j++) {
            tmp = _mm_aesdec_si128(tmp, ((__m128i*)key)[j]);
        }

        // Perform the final round of decryption
        tmp = _mm_aesdeclast_si128(tmp, ((__m128i*)key)[j]);

        // Store the decrypted block in the output
        _mm_storeu_si128(&((__m128i*)out)[i], tmp);
    }
}
int main() {

    

     // Cipher Key provided
    unsigned char userKey[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
                                 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c}; 
    
    // Input (Plaintext) provided
    unsigned char plaintext[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 
                                   0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    unsigned char key_schedule[176]; // 11 * 16 bytes = 176 bytes for AES-128

    // Perform key expansion
    AES_128_Key_Expansion(userKey, key_schedule);

    // Print the key schedule
    print_key_schedule(key_schedule);                               
    
    unsigned char ciphertext[16];
    unsigned char decryptedtext[16];

    unsigned char keySchedule[176]; // AES key schedule will be 176 bytes (11 x 16 bytes for 10 rounds + initial)

    // Key expansion to create the full key schedule from the user key
    AES_128_Key_Expansion(userKey, keySchedule);

    printf("Original Plaintext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", plaintext[i]);
    }
    printf("\n");

    // Encrypt the plaintext
    AES_ECB_encrypt(plaintext, ciphertext, sizeof(plaintext), keySchedule, 10);
    
    // Print ciphertext as hex
    printf("Ciphertext: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    AES_ECB_decrypt(ciphertext, decryptedtext, sizeof(ciphertext), keySchedule, 10);

    // Print decrypted text
    printf("Decrypted Text: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", decryptedtext[i]);
    }
    printf("\n");

    return 0;
}
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
//To run the code use the command:
>>g++ -maes -msse2 -o aes128_intrinsics aes128_intrinsics.c
>>./aes128_intrinsics
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
//Note: Make sure AES (Advanced Encryption Standard) support on a CPU using the cpuid instruction in C.
#include <stdio.h>

#define cpuid(func, ax, bx, cx, dx)           \
    __asm__ __volatile__ ("cpuid" :          \
    "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (func));

int Check_CPU_support_AES() {
    unsigned int a, b, c, d;
    cpuid(1, a, b, c, d); // Call cpuid function with function code 1
    return (c & (1 << 25)) != 0; // Check if bit 25 is set
}

int main() {
    if (Check_CPU_support_AES()) {
        printf("AES is supported on this CPU.\n");
    } else {
        printf("AES is NOT supported on this CPU.\n");
    }
    return 0;
}


