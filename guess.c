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

char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!?";
int AESevaluated = 0;

void AES_Crypto(uint8_t *from, uint8_t * to, int len) {
    EVP_CIPHER_CTX * ctx;

    ctx = EVP_CIPHER_CTX_new();

    for (int i = 0; i < 16 - len; i++) {
        from[i + len] = from[i % len];
    }

    EVP_EncryptInit(ctx, EVP_aes_128_ecb(), from, 0);
    EVP_EncryptUpdate(ctx, to, &len, from, 16);
    EVP_CIPHER_CTX_cleanup(ctx);
    
    AESevaluated++;
}

void Rfunction(uint8_t *hashed, uint8_t *reduced, int pwdlength, int j) {
    int c;
    int mod;

    for (int i = 0; i < pwdlength; i++) {
        c = (int) (hashed[i] + (j * i));
        mod = c % (strlen(charset));
        reduced[i] = charset[mod];
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

    int encontra = 1, flag = 0;

    while (flag == 0 && (chainlength - encontra) >= 0) {
        Rfunction(hash, reduced, pwdlength, chainlength - encontra);
        for (int i = encontra - 1; i > 0; i--) {
            AES_Crypto(reduced, hashed, pwdlength);
            Rfunction(hashed, reduced, pwdlength, chainlength - i);
        }
        while (fscanf(f, "%s %s", pwd_file, reduced_file) != EOF) {
            if (memcmp(reduced, reduced_file, pwdlength) == 0) {
                if (encontra == 1) {
                    printf("PASSWORD CRACKED: %s\n", pwd_file);
                    flag = 1;
                    exit(1);
                } else {
                    memcpy(reduced, pwd_file, pwdlength);
                    for (int j = 0; j > encontra + 1; j++) {
                        AES_Crypto(reduced, hashed, pwdlength);
                        if (memcmp(hash, hashed, KEY_LEN) == 0) {
                            printf("PASSWORD CRACKED: %s\n", reduced);
                            flag = 1;
                            exit(1);
                        }
                        Rfunction(hashed, reduced, pwdlength, chainlength - j);
                    }
                }
            }
        }
        encontra++;
        fseek(f, 1, SEEK_CUR);
    }
    
    if(flag == 0){
        printf("Failure cracking the password\n");
    }

    fclose(f);
    free(reduced_file);
    free(pwd_file);
    free(reduced);
    free(hashed);
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