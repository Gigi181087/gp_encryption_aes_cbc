#ifndef __GP__ENCRYPTION__AES__CBC_H_
#define __GP__ENCRYPTION__AES__CBC_H_

#include <stdint.h>
#include "src/Submodules/gp_encryption_aes/public/gp_encryption_aes_key_management/gp_encryption_aes_key_management.h"

#define GP__ENCRYPTION__AES__CBC__ERRORS__NO_ERROR          0
#define GP__ENCRYPTION__AES__CBC__ERRORS__ALLOC_FAILED      1
#define GP__ENCRYPTION__AES__CBC__ERRORS__MESSAGE_PADDING   2
#define GP__ENCRYPTION__AES__CBC__ERRORS__MESSAGE_SIZE      3
#define GP__ENCRYPTION__AES__CBC__ERRORS__UNKNOWN_ERROR     255

#ifdef __cplusplus
extern "C" {
#endif


/// @brief                          takes a message, adds padding, randomise with given initialization vector and encrypts with aes key
/// @param key                      aes key
/// @param message                  message to encrypt
/// @param initialization_vector    initialization vector for randomization
/// @return                         GP__ENCRYPTION__AES__CBC__ERRORS__NO_ERROR on success, otherwise errorcode of occured error
uint8_t gp__encryption__aes__encrypt_cbc(gp__encryption__aes__key__t* key, uint8_t* message, uint8_t initialization_vector[16]);

/// @brief                          takes a message, decrypts with aes, derandomize with given initialization_vector and removes padding
/// @param key                      aes key
/// @param message                  message to decrypt
/// @param initialization_vector    initialization vector for de-randomization
/// @return                         GP__ENCRYPTION__AES__CBC__ERRORS__NO_ERROR on success, otherwise errorcode of occured error
uint8_t gp__encryption__aes__decrypt_cbc(gp__encryption__aes__key__t* key, uint8_t* message, uint8_t initialization_vector[16]);


#ifdef __cplusplus
}
#endif

#endif // __GP__ENCRYPTION__AES__CBC_H_