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

void randomPwd(uint8_t *s, int pwdlength) {
    int num = rand();
    srand(getpid() + num);
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";

    for (int i = 0; i < pwdlength; ++i) {
        s[i] = alphanum[rand() % (sizeof (alphanum) - 1)];
    }
    s[pwdlength] = 0;
}

void genKey(uint8_t *key, uint8_t *pwd, int pwdlength) {
    int conta = 0;
    int conta2 = 0;

    while (conta < KEY_LEN) {
        if (conta2 == pwdlength) {
            conta2 = 0;
        }
        if (conta2 < pwdlength) {
            key[conta] = pwd[conta2];
            conta2++;
        }
        conta++;
    }
    key[KEY_LEN] = 0;
}

void Rfunction(uint8_t *hashed, uint8_t *reduced, int pwdlength,int i) {
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";
    int c;
    int mod;
    for (int i = 0; i < pwdlength; i++) {
        c = (int) (hashed[i] * pow(2,i));
        mod = c % ((sizeof (alphanum)) - 1);
        reduced[i] = alphanum[mod];
    }
    reduced[pwdlength] = 0;
}

void table(int pwdlength, int s, char *filename) {
    FILE *f;
    int expresult, pwdspace = 1;

    expresult = pow(2,s);
    unsigned long int rtsize = 16 * expresult;
    strcat(filename, ".txt");

    for (int i = 0; i < pwdlength; i++) {
        pwdspace *= 64;
    }

    int nrows = rtsize / (2 * pwdlength);
    int chainlength = pwdspace / nrows;

    if ((f = fopen(filename, "w")) == NULL) {
        printf("CANNOT OPEN FILE\n");
    };

    uint8_t *pwd;
    pwd = (uint8_t *) malloc(sizeof (uint8_t)*4);

    uint8_t *reduced;
    reduced = (uint8_t *) malloc(sizeof (uint8_t)*4);

    uint8_t key[KEY_LEN], hashed[KEY_LEN];

    fprintf(f, "%d\n", pwdlength);
    for (int i = 0; i < pwdspace; i++) {
        for (int l = 0; l < nrows; l++) {
            randomPwd(pwd, pwdlength);
            fprintf(f, "%s", pwd);
            genKey(key, pwd, pwdlength);
            for (int j = 0; j < chainlength; j++) {
                //ciclo demora muito tempo
                AES_Crypto(key, hashed);
                Rfunction(hashed, reduced, pwdlength,j); //modificar R function
                genKey(key, reduced, pwdlength);
            }
            fprintf(f, " %s\n", reduced);
            printf("Reduced: %s\n", reduced);
        }
    }
    fclose(f);
    free(pwd);
    free(reduced);
}

int main(int argc, char** argv) {

    if (argc < 4 || argc > 4) {
        printf("[ERRO] Nr. errado de args!\n");
        exit(1);
    }

    char filename[10];
    int pwdlength = atoi(argv[1]);
    int s = atoi(argv[2]);
    strcpy(filename, argv[3]);

    printf("Password Length: %d\n", pwdlength);
    printf("Max size of Rainbow Table: %d\n", s);
    printf("Rainbow Table file name: %s\n", filename);

    if (pwdlength < 4 || pwdlength > 8) {
        printf("Invalid Password length.Exiting... \n");
        exit(1);
    };

    if (strlen(filename) > 10) {
        printf("Invalid file name length.Exiting... \n");
        exit(1);
    }

    if (s < 0) {
        printf("Invalid s input.Exiting... \n");
        exit(1);
    }

    clock_t tic = clock();

    table(pwdlength, s, filename);

    clock_t toc = clock();

    printf("Elapsed: %f seconds\n", (double) (toc - tic) / CLOCKS_PER_SEC);

    return (EXIT_SUCCESS);
}

