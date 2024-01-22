#include "gp_encryption_aes_cbc.h"
#include "src/Submodules/gp_encryption_aes/public/gp_encryption_aes_functions/gp_encryption_aes_functions.h"
#include "src/Submodules/gp_encryption_aes/private/gp_encryption_aes_typedefs.h"
#include "src/Submodules/gp_encryption_padding/gp_encryption_padding.h"

uint8_t parse_padding_error(uint8_t);

uint8_t gp__encryption__aes__encrypt_cbc(gp__encryption__aes__key__t* key_param, uint8_t* message_param, uint8_t initialization_vector_param[16]) {
    uint8_t result;
    
    if ((result = gp__encryption__padding__add(message_param, 16)) != GP__ENCRYPTION__PADDING__ERRORS__NO_ERROR) {

        return parse_padding_error(result);
    }
    uint8_t* xor = initialization_vector_param;

    for (uint16_t i = 0; i < (sizeof(message_param) / sizeof(uint8_t)); i += 16) {

        for (uint8_t j = 0; j < 16; j++) {
            message_param[j + i] ^= xor[j];
        }
        cipher(key_param->internal_key, &message_param[i]);
        xor = &message_param[i];
    }

    return GP__ENCRYPTION__AES__CBC__ERRORS__NO_ERROR;
}

uint8_t gp__encryption__aes__decrypt_cbc(gp__encryption__aes__key__t* key_param, uint8_t* message_param, uint8_t initialization_vector_param[16]) {
    uint8_t result;
    uint8_t* xor;
    uint16_t message_length = (sizeof(message_param) / sizeof(uint8_t));

    if ((message_length % 16) != 0) {

        return GP__ENCRYPTION__AES__CBC__ERRORS__MESSAGE_SIZE;
    }

    if (message_length > 16) {
        xor = &message_param[message_length - 16];
    
    } else {
        xor = initialization_vector_param;
    }

    for (uint16_t i = message_length - 16; i >= 0; i -= 16) {

        for (uint8_t j = 0; j < 16; j++) {
            message_param[j - 16 + i] ^= xor[j];
        }
        inv_cipher(key_param->internal_key, &message_param[i]);

        if (i > 16) {
            xor = &message_param[i - 16];
    
        } else {
            xor = initialization_vector_param;
        }
    }

    if ((result = gp__encryption__padding__remove(message_param)) != GP__ENCRYPTION__PADDING__ERRORS__NO_ERROR) {

        return parse_padding_error(result);
    }

    return GP__ENCRYPTION__AES__CBC__ERRORS__NO_ERROR;
}

uint8_t parse_padding_error(uint8_t padding_error_param) {

    switch (padding_error_param) {

        case GP__ENCRYPTION__PADDING__ERRORS__PADDING_FORMAT:

            return GP__ENCRYPTION__AES__CBC__ERRORS__MESSAGE_PADDING;

        case GP__ENCRYPTION__PADDING__ERRORS__ALLOC_FAILED:

            return GP__ENCRYPTION__AES__CBC__ERRORS__ALLOC_FAILED;

        default:

            return GP__ENCRYPTION__AES__CBC__ERRORS__UNKNOWN_ERROR;
    }
}

uint8_t parse_aes_error(uint8_t aes_error_param) {

    switch (aes_error_param) {

        case GP__ENCRYPTION__AES__ERRORS_NOERROR:

            return GP__ENCRYPTION__AES__CBC__ERRORS__NO_ERROR;

        default:

            return GP__ENCRYPTION__AES__CBC__ERRORS__UNKNOWN_ERROR;
    }
}