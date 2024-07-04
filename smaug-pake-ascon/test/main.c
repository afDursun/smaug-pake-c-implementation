#include "ciphertext.h"
#include "indcpa.h"
#include "io.h"
#include "kem.h"
#include "pack.h"
#include "pake.h"
#include "parameters.h"
#include "poly.h"
#include "rng.h"
#include <stdio.h>
#include <time.h>

#define m_size 10
#define DATA_SIZE 672
#define BLOCK_SIZE 16

int main(void) {
   

    size_t i = 0; 
    unsigned char pw[32] = "12345678";
    unsigned char a_id[32] = "87654321";
    unsigned char b_id[32] = "55555555";

    const uint8_t ssid[ID_BYTES*3] = {0};
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};
    uint8_t auth_b[AUTH_SIZE];

    uint8_t ssk_a[CRYPTO_BYTES] = {0};
    uint8_t ssk_b[CRYPTO_BYTES]= {0};
    uint8_t ct[CIPHERTEXT_BYTES] = {0};
    
    uint8_t pk_prime[PAKE_A0_SEND + 16];
    uint8_t K[SHA3_256_HashSize];

    uint8_t K_bar[SHA3_256_HashSize];

    
    uint8_t entropy_input[48] = {0};
    for (i=0 ;i < 48; ++i) {
        entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);


    pake_c0(pw, ssid, pk_prime, pk, sk);
    pake_s0(pw, ssid, a_id, b_id, pk_prime, K_bar, ct, K, auth_b);
    
    
    pake_c1(pw, pk, sk, pk_prime, K_bar, ssid, a_id, b_id, ct, ssk_a);

    printf("\nsuccess...");
    printf("\nSession Key A:");
    printData(ssk_a,SHA3_256_HashSize);
    printf("***************************************\n\n\n");


    pake_s1(ssid,a_id,b_id,pk_prime,ct,K_bar,K,ssk_b);
    printf("\nsuccess...");
    printf("\nSession Key B:");
    printData(ssk_b,SHA3_256_HashSize);
    printf("***************************************\n\n\n");

    return 0;
}
