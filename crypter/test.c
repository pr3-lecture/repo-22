#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "crypto.h"

#define mu_assert(message, test) do { if (!(test)) return message; } while (0)
#define mu_run_test(test) do { char *message = test(); tests_run++; \
                                 if (message) return message; } while (0)

static int tests_run = 0;

static char* test_encrypt_output() {
	char *key = "TPERULES";
    KEY ckey;
    ckey.type = 1;
    ckey.chars = key;

	char *input = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *output = (char*)malloc(sizeof(char) * (strlen(input) + 1));
    
    encrypt(ckey, input, output);
    mu_assert("output should equal to expected output", strcmp(output, "URFVPJB[]ZN^XBJCEBVF@ZRKMJ") == 0);
    return 0;
}

static char* test_decrypt_output() {
	char *key = "TPERULES";
    KEY ckey;
    ckey.type = 1;
    ckey.chars = key;

	char *input = "URFVPJB[]ZN^XBJCEBVF@ZRKMJ";
    char *output = (char*)malloc(sizeof(char) * (strlen(input) + 1));

    decrypt(ckey, input, output);
    mu_assert("output should equal to expected output", strcmp(output, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == 0);
    return 0;
}

static char* allTests() {
    mu_run_test(test_encrypt_output);
    mu_run_test(test_decrypt_output);
    /* weitere Tests */
    return 0;
}

int main() {
    char *result = allTests();

    if (result != 0) printf("%s\n", result);
    else             printf("ALL TESTS PASSED\n");

    printf("Tests run: %d\n", tests_run);

    return result != 0;
}