#include "ciphertext.h"
#include "indcpa.h"
#include "io.h"
#include "kem.h"
#include "aes.h"
#include "pack.h"
#include "pake.h"
#include "parameters.h"
#include "poly.h"
#include "rng.h"
#include <stdio.h>
#include <time.h>
#include <openssl/aes.h>

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

    uint8_t key_a[CRYPTO_BYTES] = {0};
    uint8_t key_b[CRYPTO_BYTES]= {0};
    uint8_t ct[CIPHERTEXT_BYTES] = {0};
    
    uint8_t pk_prime[PAKE_A0_SEND];
    uint8_t K[SHA3_256_HashSize];

    uint8_t K_bar[SHA3_256_HashSize];

    
    uint8_t entropy_input[48] = {0};
    for (i=0 ;i < 48; ++i) {
        entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);

    //SendA0 => pk_prime
    //SendB0 => Auth

  //  printf("\n****************PAKE-A0****************");
    pake_a0(pw, ssid, pk_prime, pk, sk);

/*
    printf("\npk size:%d\n" , PUBLICKEY_BYTES);
    printf("sk size:%d\n" , KEM_SECRETKEY_BYTES);
    printf("\nA0 ---> B0:   ");
    printf("A(%d), pk_prime(%d) \nTotal Send %d bytes",ID_BYTES,PAKE_A0_SEND, ID_BYTES+PAKE_A0_SEND);
    printf("\n***************************************\n\n\n");
*/



    //printf("\n****************PAKE-B0****************");
    pake_b0(pw, ssid, a_id, b_id, pk_prime, K_bar, ct, K, auth_b);

/*
    printf("\nA1 <--- B0:   ");
    printf("B(%d), c(%d), Auth(%d) \nTotal Send %d bytes",ID_BYTES,CIPHERTEXT_BYTES,AUTH_SIZE,ID_BYTES+CIPHERTEXT_BYTES+AUTH_SIZE);
    printf("\n***************************************\n\n\n");
*/



  //  printf("\n****************PAKE-A1****************");
    pake_a1(pw, pk, sk, pk_prime, K_bar, ssid, a_id, b_id, ct, key_a);


    printf("\nsuccess...");
    printf("\nSession Key A:");
    printData(key_a,SHA3_256_HashSize);
    printf("***************************************\n\n\n");





  //  printf("\n****************PAKE-B1****************");
    pake_b1(ssid,a_id,b_id,pk_prime,ct,K_bar,K,key_b);


    printf("\nsuccess...");
    printf("\nSession Key B:");
    printData(key_b,SHA3_256_HashSize);
    printf("***************************************\n\n\n");

    return 0;
}
