#include <stdio.h>
#include <time.h>

#include "cpucycles.h"
#include "pake.h"
#include "parameters.h"
#include "speed_print.h"

#define NTESTS 1000

uint64_t t[NTESTS];

int main(){
    unsigned char pw[32] = "12345678";
    unsigned char a_id[32] = "87654321";
    unsigned char b_id[32] = "55555555";

    const uint8_t ssid[ID_BYTES] = {0};
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t sk[KEM_SECRETKEY_BYTES] = {0};
    uint8_t k[CRYPTO_BYTES] = {0};
    uint8_t auth_b[AUTH_SIZE];

    uint8_t key_a[CRYPTO_BYTES] = {0};
    uint8_t key_b[CRYPTO_BYTES]= {0};
    uint8_t ct[CIPHERTEXT_BYTES] = {0};
    
    uint8_t send_a0[PAKE_A0_SEND];
    uint8_t send_b0[SHA3_256_HashSize];

    int i = 0;
    clock_t srt, ed;
    clock_t overhead;

    overhead = clock();
    cpucycles();
    overhead = clock() - overhead;

    uint8_t entropy_input[48] = {0};
    for (i=0 ;i < 48; ++i) {
        entropy_input[i] = i;
    }
    randombytes_init(entropy_input, NULL, 256);

    


    srt = clock();
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        pake_a0(pw, ssid, send_a0, pk, sk);
    }
    ed = clock();
    print_results("pake_a0: ", t, NTESTS);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * NTESTS) *
                                           1000 / CLOCKS_PER_SEC / NTESTS);



    srt = clock();
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        pake_b0(pw, ssid, a_id, b_id, send_a0, send_b0, ct, k, auth_b);
    }
    ed = clock();
    print_results("pake_b0: ", t, NTESTS);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * NTESTS) *
                                           1000 / CLOCKS_PER_SEC / NTESTS);



    srt = clock();
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        pake_a1(pw, pk, sk, send_a0, send_b0, ssid, a_id, b_id, ct, key_a);
    }
    ed = clock();
    print_results("pake_a1: ", t, NTESTS);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * NTESTS) *
                                           1000 / CLOCKS_PER_SEC / NTESTS);




    srt = clock();
    for (i = 0; i < NTESTS; i++) {
        t[i] = cpucycles();
        pake_b1(ssid,a_id,b_id,send_a0,ct,auth_b,k,key_b);
    }
    ed = clock();
    print_results("pake_b1: ", t, NTESTS);
    printf("time elapsed: %.8fms\n\n", (double)(ed - srt - overhead * NTESTS) *
                                           1000 / CLOCKS_PER_SEC / NTESTS);

}
