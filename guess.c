#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <time.h>
#include <math.h>

#define KEY_LEN 16 

void AES_Crypto(uint8_t *from, uint8_t * to, int len) {
    EVP_CIPHER_CTX * ctx;

    ctx = EVP_CIPHER_CTX_new();

    for (int i = 0; i < 16 - len; i++) {
        from[i + len] = from[i % len];
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), from, 0);
    EVP_EncryptUpdate(ctx, to, &len, from, 16);
    EVP_CIPHER_CTX_cleanup(ctx);
}

void Rfunction(uint8_t *hashed, uint8_t *reduced, int pwdlength, int j) {
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";
    int c;
    int mod;

    for (int i = 0; i < pwdlength; i++) {
        c = (int) (hashed[i] + (j * i));
        mod = c % ((sizeof (alphanum)) - 1);
        reduced[i] = alphanum[mod];
    }
    reduced[pwdlength] = 0;
}

void guess(char *filename, uint8_t *hash) {
    strcat(filename, ".txt");
    FILE *f;
    int pwdlength, chainlength, cracked = 0;

    if ((f = fopen(filename, "r")) == NULL) {
        printf("CANNOT OPEN FILE\n");
    };

    fscanf(f, "%d %d", &pwdlength, &chainlength);

    uint8_t *reduced_file;
    reduced_file = (uint8_t *) malloc(sizeof (uint8_t) * pwdlength);

    uint8_t *pwd_file;
    pwd_file = (uint8_t *) malloc(sizeof (uint8_t) * pwdlength);

    uint8_t *reduced;
    reduced = (uint8_t *) malloc(sizeof (uint8_t) * pwdlength);

    uint8_t *hashed;
    hashed = (uint8_t *) malloc(sizeof (uint8_t) * pwdlength);

    int encontra = 1;

    Rfunction(hash, reduced, pwdlength, 0);
    for (int i = 1; i < chainlength; i++) {
        AES_Crypto(reduced, hashed, pwdlength);
        Rfunction(hashed, reduced, pwdlength, i);
    }

    while (fscanf(f, "%s %s", pwd_file, reduced_file) != EOF) {
        if (memcmp(reduced, reduced_file, pwdlength) == 0) {
            cracked = 1;
            printf("PASSWORD CRACKED: %s\n", pwd_file);
            break;
        }
    }

    int conta = 0;
    
    while (cracked != 1 || encontra != chainlength) {
        Rfunction(hash, reduced, pwdlength, 0);
        for (int i = 1; i < chainlength - encontra; i++) {
            AES_Crypto(reduced, hashed, pwdlength);
            Rfunction(hashed, reduced, pwdlength, i);
        }
        for (int i = 0; i < encontra; i++) {
            AES_Crypto(reduced, hashed, pwdlength);
            Rfunction(hashed, reduced, pwdlength, i);
        }
        while (fscanf(f, "%s %s", pwd_file, reduced_file) != EOF) {
            if (memcmp(reduced, reduced_file, pwdlength) == 0) {
                int h = 0;
                while (h == 0) {
                    AES_Crypto(pwd_file, hashed, pwdlength);
                    if (memcmp(hash, hashed,pwdlength) == 0) {
                        printf("PASSWORD CRACKED: %s\n", reduced);
                        cracked = 1;
                        h = 1; 
                    }
                    else{
                        Rfunction(hashed, reduced, pwdlength, conta);
                    }
                    conta++;
                }

            }
        }
        encontra++;
    }

    fclose(f);
    free(reduced_file);
    free(pwd_file);
    free(reduced);
}

int main(int argc, char** argv) {
    if (argc < 3 || argc > 3) {
        printf("[ERRO] Nr. errado de args!\n");
        exit(1);
    }

    char *filename = argv[1];
    uint8_t *hash2 = argv[2];
    uint8_t hash[KEY_LEN];

    printf("Rainbow Table file: %s\n", filename);
    printf("H(P): %s\n", hash2);

    if (strlen(hash2) < 32 || strlen(hash2) > 32) {
        printf("Invalid Password length.Exiting... \n");
        exit(1);
    }

    /*
        hash[0] = 248;
        hash[1] = 52;
        hash[2] = 12;
        hash[3] = 131;
        hash[4] = 109;
        hash[5] = 65;
        hash[6] = 247;
        hash[7] = 124;
        hash[8] = 217;
        hash[9] = 39;
        hash[10] = 8;
        hash[11] = 187;
        hash[12] = 213;
        hash[13] = 68;
        hash[14] = 60;
        hash[15] = 190;
     * */

    hash[0] = 83;
    hash[1] = 33;
    hash[2] = 171;
    hash[3] = 179;
    hash[4] = 181;
    hash[5] = 127;
    hash[6] = 83;
    hash[7] = 94;
    hash[8] = 14;
    hash[9] = 49;
    hash[10] = 134;
    hash[11] = 183;
    hash[12] = 163;
    hash[13] = 32;
    hash[14] = 77;
    hash[15] = 255;



    guess(filename, hash);


    return (EXIT_SUCCESS);
}