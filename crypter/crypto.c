#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "crypto.h"

int valueFromChar(char c) {
    return c - 'A' + 1;
}

int charFromValue(char c) {
    return c + 'A' - 1;
}

int checkXORKey(KEY key) {
    if(key.type != 1) {
        return E_KEY_ILLEGAL_TYPE;
    }
    
    int key_length = strlen(key.chars);
    if(key_length < 1) {
        return E_KEY_TOO_SHORT;
    }
    return 0;
}

int xor(KEY key, const char *input, char* output, char minValidInputChar, char maxValidInputChar) {
    int error = checkXORKey(key);
    if(error != 0) {
        return error;
    }

    int key_length = strlen(key.chars);
    //validate key
    for(int i = 0; i < key_length; i++) {
        char key_char = key.chars[i];
        if(key_char < '@' || key_char > '_') {
            return E_CYPHER_ILLEGAL_CHAR;
        }
    }

    for(int i = 0; input[i]; i++) {
        //get and validate current input char
        char input_char = input[i];
        if(input_char < minValidInputChar || input_char > maxValidInputChar) {
            return E_MESSAGE_ILLEGAL_CHAR;
        }
        int input_value = valueFromChar(input_char);
        
        //get current key char
        char key_char = key.chars[i % key_length];
        int key_value = valueFromChar(key_char);

        //xor
        char output_value = input_value ^ key_value;

        output[i] = charFromValue(output_value);
    }
    return 0;
}

int encrypt(KEY key, const char *input, char* output) {
    return xor(key, input, output, 'A', 'Z');
}

int decrypt(KEY key, const char *input, char* output) {
    return xor(key, input, output, '@', '_');
}
