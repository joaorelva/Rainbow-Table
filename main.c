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

void random_pwd(uint8_t *s, const int len) {
    int num = rand();
    srand(getpid() + num);
    static const char alphanum[] =
            "0123456789!?"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof (alphanum) - 1)];
    }
    s[len] = 0;
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

void Rfunction(uint8_t *hashed, uint8_t *reduced, int pwdl) {
    char alphanum[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";
    int c;
    int mod;
    for (int i = 0; i < pwdl; i++) {
        c = (int) hashed[i];
        mod = c % ((sizeof (alphanum)) - 1);
        reduced[i] = alphanum[mod];
    }
    reduced[pwdl] = 0;
}

int calc_exp_2(int s) {
    int result = 1;
    for (int i = 0; i < s; i++) {
        result *= 2;
    }
    return result;
}

void table(int pwdlength, int s, char *filename) {
    FILE *f;
    int exp_result,pwdspace=1;
    exp_result = calc_exp_2(s);
    unsigned long long int rb_size = 16 * exp_result;
    strcat(filename, ".txt");
    
    for(int i=0;i<pwdlength;i++){
        pwdspace*=64;
    }
    
    int n_rows = rb_size / (2 * pwdlength);
    int chain_length = pwdspace / n_rows;

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
        for (int l = 0; l < n_rows; l++) {
            random_pwd(pwd, pwdlength);
            fprintf(f, "%s", pwd);
            gen_key(key, pwd, pwdlength);
            for (int j = 0; j < chain_length; j++) {
                AES_Crypto(key, hashed);
                Rfunction(hashed, reduced, pwdlength); //modificar R function
                gen_key(key, reduced, pwdlength);
            }
            fprintf(f, " %s\n", reduced);
        }
    }
    fclose(f);
    free(pwd);
    free(reduced);
}

int main(int argc, char** argv) {

    char filename[20];
    int rb_size, exp_result;

    if (argc < 4 || argc > 4) {
        printf("[ERRO] Nr. errado de args!\n");
        exit(1);
    }

    int pwd_length = atoi(argv[1]);
    int s = atoi(argv[2]);
    strcpy(filename, argv[3]);

    printf("Password Length: %d\n", pwd_length);
    printf("Max size of Rainbow Table: %d\n", s);
    printf("Rainbow Table file name: %s\n", filename);


    if (pwd_length < 4 || pwd_length > 8) {
        printf("Invalid Password length.Exiting... \n");
        exit(1);
    };

    //falta proteção do s e do filename
    clock_t tic = clock();

    table(pwd_length, s, filename);

    clock_t toc = clock();

    printf("Elapsed: %f seconds\n", (double) (toc - tic) / CLOCKS_PER_SEC);

    return (EXIT_SUCCESS);
}

