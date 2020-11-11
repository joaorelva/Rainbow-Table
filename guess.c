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

#define KEY_LEN 16 

void intarrayrand(int *r, int pwdl) {
    for (int i = 0; i < pwdl; i++) {
        int num1 = rand();
        srand(getpid() + num1);
        int num2 = rand() % KEY_LEN;
        for (int j = 0; j < pwdl; j++) {
            while (r[j] == num2) {
                num2 = rand() % KEY_LEN;
            }
        }
        r[i] = num2;
    }
}

void AES_Crypto(uint8_t *key, uint8_t *hashed) {

    EVP_CIPHER_CTX * ctx;
    int keylen = KEY_LEN;

    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit(ctx, EVP_aes_128_ecb(), key, NULL, 1);

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    uint8_t ciphertext[KEY_LEN];
    EVP_CipherUpdate(ctx, ciphertext, &keylen, key, keylen);

    EVP_CipherFinal(ctx, ciphertext, &keylen);
    EVP_CIPHER_CTX_free(ctx);

    strcpy(hashed, ciphertext);
}

void gen_key(uint8_t *key, uint8_t *pwd, const int len) {
    int conta = 0;
    int conta2 = 0;

    while (conta < KEY_LEN) {
        if (conta2 == len) {
            conta2 = 0;
        }
        if (conta2 < len) {
            key[conta] = pwd[conta2];
            conta2++;
        }
        conta++;
    }
    key[KEY_LEN] = 0;
}

void Rfunction(uint8_t *hashed, uint8_t *reduced, int pwdl, int r[]) {
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";
    int c;
    int mod;
    for (int i = 0; i < pwdl; i++) {
        c = (int) hashed[r[i]];
        mod = c % ((sizeof (alphanum)) - 1);
        reduced[i] = alphanum[mod];
    }
    reduced[pwdl] = 0;
}

void guess(char *filename, uint8_t *hash) {
    strcat(filename, ".txt");
    FILE *f;
    int pwdlength, cracked = 0;

    if ((f = fopen(filename, "r")) == NULL) {
        printf("CANNOT OPEN FILE\n");
    };

    fscanf(f, "%d", &pwdlength);

    uint8_t reduced_file[pwdlength];
    uint8_t pwd[pwdlength];
    uint8_t reduced[pwdlength];
    uint8_t key[KEY_LEN];
    uint8_t hash2[KEY_LEN];
    uint8_t reduced_ant[pwdlength];

    int r[pwdlength];
    intarrayrand(r, pwdlength);
    Rfunction(hash, reduced, pwdlength, r);

    strcpy(reduced_ant, reduced);

    while (fscanf(f, "%s %s", pwd, reduced_file) != EOF || cracked == 1) {
        strcpy(reduced, reduced_ant);
        if (strcmp(reduced, reduced_file) == 0) {
            cracked = 1;
            printf("PASSWORD CRACKED: %s\n", pwd);
        } else {
            for (int i = 0; i < 8; i++) {
                gen_key(key, reduced, pwdlength);
                AES_Crypto(key, hash2);
                Rfunction(hash2, reduced, pwdlength, r);
                if (strcmp(reduced, reduced_file) == 0) {
                    printf("PASSWORD CRACKED: %s\n", pwd);
                    cracked = 1;
                }
            }
        }
    }
    fclose(f);
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
    };

//Test
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


    guess(filename, hash);


    return (EXIT_SUCCESS);
}
