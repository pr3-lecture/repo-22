#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "crypto.h"

int main() {
    char *input = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char *output = (char*)malloc(sizeof(char) * strlen(input));
    char *key = "TPERULES";
    KEY ckey;
    ckey.type = 1;
    ckey.chars = key;
    
    encrypt(ckey, input, output);
    
    char *result = (char*)malloc(sizeof(char) * strlen(output));
    decrypt(ckey, output, result);
    
    printf("INPUT:  %s\n", input);
    printf("KEY:    %s\n", key);
    printf("OUTPUT: %s\n", output);
    printf("RESULT: %s\n", result);
    
    return 0;
}