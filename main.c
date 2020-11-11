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

int calc_exp_2(int s) {
    int result = 1;
    for (int i = 0; i < s; i++) {
        result *= 2;
    }
    return result;
}

void table(int pwdlength, int s, char *filename) {
    FILE *f;
    int exp_result;
    exp_result = calc_exp_2(s);
    unsigned long long int rb_size = 16 * exp_result;
    printf("Rainbow Table Size: %d\n", rb_size);
    strcat(filename, ".txt");

    int k = s-2;
    printf("k: %d\n", k);
    int n_linhas;
    n_linhas = rb_size / ((pwdlength * 2) + 1);
    printf("N linhas: %d\n\n", n_linhas);

    if ((f = fopen(filename, "w")) == NULL) {
        printf("CANNOT OPEN FILE\n");
    };
    fprintf(f, "%d\n", pwdlength);
    for (int i = 0; i < (64 * 64 * 64 * 64); i++) {
        //--------------------------GERA PASSWORD E KEY-------------------------
        uint8_t pwd[pwdlength];
        random_pwd(pwd, pwdlength);
        printf("PASSWORD: %s\n", pwd);
        uint8_t key[KEY_LEN];
        gen_key(key, pwd, pwdlength);
        printf("KEY: %s\n", key);
        //ESCREVE PASSWORD EM FICHEIRO DE TEXTO
        uint8_t reduced[pwdlength];
        fprintf(f, "%s", pwd);
        //--------------------------GERA HASH DA PASSWORD-----------------------
        for (int j = 0; j < k; j++) {
            uint8_t hashed[KEY_LEN];
            AES_Crypto(key, hashed);
            //--------------------------FAZ A REDUÇÃO DA HASH-------------------
            int r[pwdlength];
            intarrayrand(r, pwdlength);
            Rfunction(hashed, reduced, pwdlength, r);
            gen_key(key, reduced, pwdlength);
            printf("Reduced %d : %s\n", j + 1, reduced);
        }
        printf("REDUCED FINAL: %s\n", reduced);
        printf("\n-------------------------------------\n");
        fprintf(f, " %s\n", reduced);
    }
    fclose(f);
}

int main(int argc, char** argv) {

    char filename[20];
    int rb_size, exp_result;

    if (argc < 4 || argc > 4) {
        printf("[ERRO] Nr. errado de args!\n");
        exit(1);
    }

    fflush(stdin);
    fflush(stdout);

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
    table(pwd_length, s, filename);


    return (EXIT_SUCCESS);
}

