#include <string.h>
#include <assert.h>
#include <stdio.h>

typedef enum auth_return {
    AUTH_VALID,
    AUTH_INVALID,
    AUTH_ERRSIZE,
} auth_return_t;

#define PASS_BUFSIZE 20
#define PASSWORD "password"

auth_return_t check_authentication(char* password) {
    static_assert(sizeof(PASSWORD) < PASS_BUFSIZE, "Password is longer than buffer size.");
    char password_buffer[PASS_BUFSIZE];
    strncpy(password_buffer, password, 20);
    if (password_buffer[PASS_BUFSIZE-1] != '\0') return AUTH_ERRSIZE;
    if (strcmp(password_buffer, PASSWORD) == 0) {
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
    }   
}
