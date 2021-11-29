#include "string.h"
#include "assert.h"
#include "stdio.h"
#include "stdint.h"
// for SHA-3
#include "openssl/evp.h"
#include "openssl/sha.h"

typedef enum auth_return {
    AUTH_VALID,
    AUTH_INVALID,
    AUTH_ERRSIZE,
    AUTH_ERRALLOC,
    AUTH_ERRDIGEST,
} auth_return_t;

#define PASS_BUFSIZE 20
// Store hash as raw byte array for easy comparison.
uint8_t valid_hash[64] = {222, 153, 123, 216, 88, 4, 200, 73, 47, 147, 188, 49, 118, 54, 10, 70, 243, 77, 56, 244, 11, 3, 93, 30, 39, 6, 224, 245, 67, 238, 192, 180, 149, 199, 212, 170, 3, 71, 164, 183, 156, 60, 218, 200, 222, 136, 218, 54, 37, 179, 223, 38, 236, 46, 242, 12, 107, 234, 59, 127, 237, 213, 224, 253};

auth_return_t check_authentication(const char* password) {
    char password_buffer[PASS_BUFSIZE];
    strncpy(password_buffer, password, 20);

    // strcpy will always fill rest of buffer with null so if last char is not null
    // that means that user must have inputted a string longer than 20 characters.
    if (password_buffer[PASS_BUFSIZE-1] != '\0') return AUTH_ERRSIZE;

    // generate SHA-3 hash for inputted password
    // taken from https://stackoverflow.com/a/62605880
    uint32_t digest_length = SHA512_DIGEST_LENGTH;
    const EVP_MD* algorithm = EVP_sha3_512();
    uint8_t* digest = (uint8_t*)(OPENSSL_malloc(digest_length));
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    // if allocating either of these failed, error
    if (digest == NULL || context == NULL) return AUTH_ERRALLOC;

    // generate digest, return error on first failed operation
    if (EVP_DigestInit_ex(context, algorithm, NULL) != 1 ||
        EVP_DigestUpdate(context, password, PASS_BUFSIZE) != 1 ||
        EVP_DigestFinal_ex(context, digest, &digest_length) != 1) {
        return AUTH_ERRDIGEST;
    }

    EVP_MD_CTX_destroy(context);

    // compare to valid hash
    int cmp = memcmp(digest, valid_hash, 64);
    OPENSSL_free(digest);

    if (cmp == 0) {
        return AUTH_VALID;
    } else {
        return AUTH_INVALID;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <password>\n", argv[0]);
        return 1;
    }

    switch (check_authentication(argv[1])) {
    case AUTH_VALID:
        printf("Access Granted.\n");
        break;
    case AUTH_INVALID:
        printf("Access Denied.\n");
        break;
    case AUTH_ERRSIZE:
        printf("Invalid password size!\n");
        break;
    case AUTH_ERRALLOC:
        printf("Out of memory!\n");
        break;
    case AUTH_ERRDIGEST:
        printf("Failed to hash password!\n");
        break;
    }
}
