#include <stddef.h>
#include <stdint.h>
#include "ciphertext.h"
#include "indcpa.h"
#include "io.h"
#include "pack.h"
#include "pake.h"
#include "parameters.h"
#include "poly.h"
#include "rng.h"
#include "kem.h"
#include <stdio.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "api.h"
#include "crypto_aead.h"

#define BLOCK_SIZE 16


void concatenate_s0(unsigned char* auth_b, const unsigned char* ssid, const unsigned char* a_id, 
                 const unsigned char* b_id, const unsigned char* pw, const unsigned char* pk_prime, 
                 const unsigned char* ct, const unsigned char* k) {
    int i;

    for(i = 0; i < ID_BYTES; i++ ){
        auth_b[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES; i++ ){
        auth_b[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES; i++ ){
        auth_b[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PW_BYTES; i++ ){
        auth_b[i + ID_BYTES*3] = pw[i];
    } 

    for(i = 0; i < PAKE_A0_SEND; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES] = pk_prime[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES; i++ ){
        auth_b[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES] = k[i];
    } 
}

void concatenate_c1_auth(unsigned char* auth, const unsigned char* ssid, const unsigned char* a_id, 
               const unsigned char* b_id, const unsigned char* pw, const unsigned char* pk_prime, 
               const unsigned char* ct, const unsigned char* k_prime) {
    int i;

    for(i = 0; i < ID_BYTES; i++ ){
        auth[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES; i++ ){
        auth[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES; i++ ){
        auth[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PW_BYTES; i++ ){
        auth[i + ID_BYTES*3] = pw[i];
    } 

    for(i = 0; i < PAKE_A0_SEND; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES] = pk_prime[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < CRYPTO_BYTES; i++ ){
        auth[i + ID_BYTES*3 + PW_BYTES + PAKE_A0_SEND + CIPHERTEXT_BYTES] = k_prime[i];
    } 
}

void concatenate_c1(unsigned char* hash_array, const unsigned char* ssid, const unsigned char* a_id, 
                    const unsigned char* b_id, const unsigned char* pk_prime, const unsigned char* ct, 
                    const unsigned char* K_bar_prime, const unsigned char* k_prime) {
    int i;

    for(i = 0; i < ID_BYTES; i++ ){
        hash_array[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES; i++ ){
        hash_array[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES; i++ ){
        hash_array[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PAKE_A0_SEND; i++ ){
        hash_array[i + ID_BYTES*3] = pk_prime[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES; i++ ){
        hash_array[i + ID_BYTES*3 + PAKE_A0_SEND] = ct[i];
    } 

    for(i = 0; i < SHA3_256_HashSize; i++ ){
        hash_array[i + ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES] = K_bar_prime[i];
    } 

    for(i = 0; i < CRYPTO_BYTES; i++ ){
        hash_array[i + ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + SHA3_256_HashSize] = k_prime[i];
    } 
}

void construct_ascon_key(unsigned char* key, const unsigned char* ssid, const unsigned char* pw) {
    int i;

    for(i = 0; i < ID_BYTES*3; i++ ){
        key[i] = ssid[i];
    } 
    
    for(i = 0; i < PW_BYTES; i++ ){
        key[i + (ID_BYTES*3)] = pw[i];
    }
}

void print(unsigned char c, unsigned char* x, unsigned long long xlen) {
  unsigned long long i;
  printf("%c[%d]=", c, (int)xlen);
  for (i = 0; i < xlen; ++i) printf("%02x", x[i]);
  printf("\n");
}
void printData(const uint8_t *data, size_t dataSize) {
    for (size_t i = 0; i < dataSize; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}


void pake_c0(const unsigned char *pw, const uint8_t *ssid, uint8_t *pk_prime, uint8_t *pk, uint8_t *sk) {

unsigned char n[CRYPTO_NPUBBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
                                       8, 9, 10, 11, 12, 13, 14, 15};

  unsigned char a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  unsigned char m[16+2] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,16,17};
  unsigned char c11[32], h[32], t[32];
  unsigned long long alen = 16;
  unsigned long long mlen = 16+2;
  unsigned long long c11len = CRYPTO_ABYTES;
  int result = 0;

    
    int i;
    uint8_t key[16] = "my_128_bit_key";
    uint8_t components[PAKE_A0_SEND];
    unsigned char encrypted_components[PAKE_A0_SEND + CRYPTO_ABYTES]; 
    unsigned long long encrypted_length;
    
    
    crypto_kem_keypair(pk, sk);

    construct_ascon_key(key, ssid, pw); // key = (ssid || pw)

    for(i = 0; i < PUBLICKEY_BYTES ; i++ ){
        components[i] = pk[i];
    } 
    
    crypto_aead_encrypt(encrypted_components, &encrypted_length, components, PAKE_A0_SEND, a, alen, (void*)0, n, key);

    memcpy(pk_prime, encrypted_components, PAKE_A0_SEND + CRYPTO_ABYTES);


}

void pake_s0(const unsigned char *pw, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id,  
                    uint8_t *pk_prime, uint8_t *K_bar,uint8_t *ct,uint8_t *K,uint8_t *auth_b){
    unsigned char a[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    unsigned long long alen = 16;
    unsigned char n[CRYPTO_NPUBBYTES] = {0, 1, 2,  3,  4,  5,  6,  7,
                                       8, 9, 10, 11, 12, 13, 14, 15};
    
    uint8_t key[16] = "my_128_bit_key";
    int i;
    uint8_t pk[PUBLICKEY_BYTES] = {0};
    uint8_t components[PAKE_A0_SEND];
    unsigned char decrypted_components[PAKE_A0_SEND]; 
    unsigned long long decrypted_length;
    
    construct_ascon_key(key, ssid, pw); // key = (ssid || pw)
    crypto_aead_decrypt(decrypted_components, &decrypted_length, (void*)0, pk_prime, PAKE_A0_SEND + CRYPTO_ABYTES, a, alen, n, key);
    memcpy(components, decrypted_components, PAKE_A0_SEND);

    for(i = 0 ; i < PUBLICKEY_BYTES ; i++){
        pk[i] = components[i];
    }
    
    crypto_kem_encap(ct, K, pk);

    concatenate_s0(auth_b, ssid, a_id, b_id, pw, pk_prime, ct, K);

    hash_h(K_bar, auth_b, AUTH_SIZE);

   

}


void pake_c1(const unsigned char *pw, uint8_t *pk, uint8_t *sk, uint8_t *pk_prime, uint8_t *K_bar, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *ct, uint8_t *key_a){
    
    uint8_t k_prime[CRYPTO_BYTES];
    int i;
    int HASH_SIZE = ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + SHA3_256_HashSize + CRYPTO_BYTES;
    uint8_t auth[AUTH_SIZE];
    uint8_t K_bar_prime[SHA3_256_HashSize];
    uint8_t hash_array[HASH_SIZE];

    crypto_kem_decap(k_prime, sk, pk, ct);
    
    
    concatenate_c1_auth(auth, ssid, a_id, b_id, pw, pk_prime, ct, k_prime);

    hash_h(K_bar_prime, auth, AUTH_SIZE);

    if (memcmp(K_bar_prime, K_bar, SHA3_256_HashSize) == 0) {
        concatenate_c1(hash_array, ssid, a_id, b_id, pk_prime, ct, K_bar_prime, k_prime);
        hash_h(key_a, hash_array, HASH_SIZE);
    } else {
        printf("Auth Failed....\n");
    }
    
    

}

void pake_s1(const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *pk_prime, uint8_t *ct, uint8_t *K_bar, uint8_t *K, uint8_t *key_b){
    
    int HASH_SIZE = ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES + SHA3_256_HashSize + CRYPTO_BYTES;
    uint8_t hash_array[HASH_SIZE];
    uint8_t K_bar_prime[SHA3_256_HashSize];
    int i;

    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i] = ssid[i];
    } 
    
    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i + ID_BYTES] = a_id[i];
    } 

    for(i = 0; i < ID_BYTES ; i++ ){
        hash_array[i + ID_BYTES*2] = b_id[i];
    } 

    for(i = 0; i < PAKE_A0_SEND ; i++ ){
        hash_array[i + ID_BYTES*3 ] = pk_prime[i];
    } 

    for(i = 0; i < CIPHERTEXT_BYTES ; i++ ){
        hash_array[i + ID_BYTES*3  + PAKE_A0_SEND] = ct[i];
    } 


    for(i = 0; i < SHA3_256_HashSize ; i++ ){
        hash_array[i + ID_BYTES*3 + PAKE_A0_SEND + CIPHERTEXT_BYTES] = K_bar[i];
    } 

    for(i = 0; i < CRYPTO_BYTES ; i++ ){
        hash_array[i + ID_BYTES*3  + PAKE_A0_SEND + CIPHERTEXT_BYTES+ SHA3_256_HashSize] = K[i];
    } 

    hash_h(key_b, hash_array, HASH_SIZE);


}
