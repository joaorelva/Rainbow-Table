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

void randomPwd(uint8_t *s, int pwdlength) {
    int num = rand();
    srand(getpid() + num);
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";

    for (int i = 0; i < pwdlength; ++i) {
        s[i] = alphanum[rand() % (sizeof (alphanum) - 1)];
    }
    s[pwdlength] = 0;
}

void Rfunction(uint8_t *hashed, uint8_t *reduced, int pwdlength, int j) {
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";
    int c;
    int mod;

    for (int i = 0; i < pwdlength; i++) {
        //c = (int) (hashed[i] * (j + 1));
        c = (int) (hashed[i] + (j*i));
        mod = c % ((sizeof (alphanum)) - 1);
        reduced[i] = alphanum[mod];
    }
    reduced[pwdlength] = 0;
}

void table(int pwdlength, int s, char *filename) {
    FILE *f;
    int expresult, pwdspace = 1;

    expresult = pow(2, s);
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
    pwd = (uint8_t *) malloc(sizeof (uint8_t) * pwdlength);

    uint8_t *reduced;
    reduced = (uint8_t *) malloc(sizeof (uint8_t) * pwdlength);

    uint8_t *key;
    key = (uint8_t *) malloc(sizeof (uint8_t) * KEY_LEN);

    uint8_t *hashed;
    hashed = (uint8_t *) malloc(sizeof (uint8_t) * KEY_LEN);

    fprintf(f, "%d %d\n", pwdlength, chainlength);

    for (int l = 0; l < nrows; l++) {
        randomPwd(pwd, pwdlength);
        printf("Entrypoint: %s -->", pwd);
        fwrite(pwd, 1, pwdlength, f);
        fputc(' ', f);
        for (int j = 0; j < chainlength; j++) {
            //printf("Pass: %s -> ", pwd);
            AES_Crypto(pwd, hashed, pwdlength);
            //printf("Key: %s\n", pwd);
            Rfunction(hashed, reduced, pwdlength, j);
            //printf("R: %s\n", reduced);
            pwd[pwdlength] = 0;
            memcpy(pwd, reduced, pwdlength);
        }
        //printf("R: %s\n", pwd);
        fwrite(reduced, 1, pwdlength, f);
        printf(" Endpoint: %s\n", reduced);
        fputc('\n', f);
    }
    fclose(f);
    free(pwd);
    free(reduced);
    free(key);
    free(hashed);
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

