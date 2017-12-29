#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "crypto.h"

int main(int argc, char** argv) {
    //check for executable name
    if (argc < 1) {
        fprintf(stderr, "Name of executable not defined\n");
        return EXIT_FAILURE;
    }
    char* name = argv[0];

    //check for key
    if (argc < 2) {
        fprintf(stderr, "Missing key as first argument\n");
        return EXIT_FAILURE;
    }
    char* keyChars = argv[1];

    //check for filename or use stdin
    FILE* file;
    if (argc > 2) {
        char* filename = argv[2];
        file = fopen(filename, "r");
        if(!file) {
            fprintf(stderr, "Could not open file \"%s\" error: %s\n", filename, strerror(errno));
            return EXIT_FAILURE;
        }
    } else {
        file = stdin;
    }

    //read file into memory
    char* input = NULL;
    size_t buffLen;
    ssize_t len;
    if((len = getline(&input, &buffLen, file)) < 0) {
        fprintf(stderr, "Could not read from input. error: %s\n", strerror(errno));
        free(input);
        fclose(file);
        return EXIT_FAILURE; 
    }
    //remove new line char if exists
    if(input[len - 1] == '\n') {
        input[len - 1] = '\0';
        len--;
    }

    printf("input: %s\n", input);
    KEY key;
    key.type = 1;
    key.chars = keyChars;

    int inputLength = strlen(input);
    char* output = (char*)malloc(sizeof(char) * (inputLength + 1));
    int result;

    if (strcmp(name, "./encrypt") == 0) {
        result = encrypt(key, input, output);
    } else if (strcmp(name, "./decrypt") == 0) {
        result = decrypt(key, input, output);
    } else {
        fprintf(stderr, "%s is not supported.\n", name);
        free(input);
        free(output);
        fclose(file);
        return EXIT_FAILURE;
    }

    if (result != 0) {
        fprintf(stderr, "%s failed. error: %s\n", name, cryptoErrorString(result));
        free(input);
        free(output);
        fclose(file);
        return EXIT_FAILURE;
    }

    printf("%s\n", output);
    free(input);
    free(output);
    fclose(file);

    return EXIT_SUCCESS;
}
