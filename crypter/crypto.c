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
    //validate key
    for(int i = 0; i < key_length; i++) {
        char key_char = key.chars[i];
        if(key_char < '@' || key_char > '_') {
            return E_KEY_ILLEGAL_CHAR;
        }
    }
    return 0;
}

int xor(KEY key, const char *input, char* output, char minValidInputChar, char maxValidInputChar, int invalidInputCharErrorCode) {
    int error = checkXORKey(key);
    if(error != 0) {
        return error;
    }

    int key_length = strlen(key.chars);
    
    int i = 0;
    for(i = 0; input[i]; i++) {
        //get and validate current input char
        char input_char = input[i];
        if(input_char < minValidInputChar || input_char > maxValidInputChar) {
            return invalidInputCharErrorCode;
        }
        int input_value = valueFromChar(input_char);
        
        //get current key char
        char key_char = key.chars[i % key_length];
        int key_value = valueFromChar(key_char);

        //xor
        char output_value = input_value ^ key_value;

        output[i] = charFromValue(output_value);
    }
    output[i] = '\0';
    return 0;
}

int encrypt(KEY key, const char *input, char* output) {
    return xor(key, input, output, 'A', 'Z', E_MESSAGE_ILLEGAL_CHAR);
}

int decrypt(KEY key, const char *input, char* output) {
    return xor(key, input, output, '@', '_', E_CYPHER_ILLEGAL_CHAR);
}

char* cryptoErrorString(int error) {
    switch (error) {
        case E_KEY_TOO_SHORT: return "Length of key not sufficient.";
        case E_KEY_ILLEGAL_CHAR: return "Key contains illegal characters.";
        case E_MESSAGE_ILLEGAL_CHAR: return "Message contains illegal characters.";
        case E_CYPHER_ILLEGAL_CHAR: return "Cypher text contains illegal characters.";
        case E_KEY_ILLEGAL_TYPE: return "Key type is illegal.";
        default: return "No error";
    }
}
