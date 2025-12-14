#ifndef CRYPTO_COMMON_H
#define CRYPTO_COMMON_H

#include <stdio.h>
#include <string.h>
#include "mbedtls/pk.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/md.h"
#include "mbedtls/gcm.h"

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------------------------------------
// AES / Key constants
// -----------------------------------------------------------------------------
#define AES_KEY_SIZE    32   // 256-bit AES key
#define AES_IV_SIZE     12   // GCM standard IV size
#define AES_TAG_SIZE    16   // GCM tag size

// -----------------------------------------------------------------------------
// Function prototypes
// -----------------------------------------------------------------------------

/**
 * @brief Generate a new EC keypair for curve SECP256R1
 * 
 * @param keypair pointer to initialized mbedtls_pk_context
 * @return int 0 on success, otherwise mbedtls error code
 */
int generate_ec_keypair(mbedtls_pk_context *keypair);

/**
 * @brief Compute ECDH shared secret given our private key and peer public point.
 * 
 * @param private_key pointer to mbedtls_pk_context with our private key
 * @param peer_public pointer to peer’s mbedtls_ecp_point
 * @param secret buffer to write shared secret into
 * @param secret_len pointer to size_t to receive secret length
 * @return int 0 on success
 */
int compute_shared_secret(mbedtls_pk_context *private_key,
                          mbedtls_ecp_point *peer_public,
                          unsigned char *secret, size_t *secret_len);

/**
 * @brief Simple SHA-256-based KDF.
 * 
 * @param input input data (e.g. shared secret)
 * @param input_len length of input
 * @param output output buffer
 * @param output_len desired output length (<= 32)
 */
int kdf_sha256(unsigned char *input, size_t input_len,
               unsigned char *output, size_t output_len);


/**
 * @brief Build a random IV for every encryption.
 * 
 * @param iv initialization vector (12 bytes)
 * @param iv_len initialization vector length
 */
int generate_random_iv(unsigned char *iv, size_t iv_len);

/**
 * @brief Encrypt data using AES-GCM.
 * 
 * @param key AES key (32 bytes)
 * @param iv initialization vector (12 bytes)
 * @param input plaintext
 * @param input_len plaintext length
 * @param output ciphertext output buffer
 * @param tag 16-byte authentication tag output
 */
int aes_gcm_encrypt(unsigned char *key, unsigned char *iv,
                    unsigned char *input, size_t input_len,
                    unsigned char *output, unsigned char *tag);

/**
 * @brief Decrypt AES-GCM encrypted data and verify tag.
 * 
 * @param key AES key
 * @param iv initialization vector
 * @param input ciphertext
 * @param input_len ciphertext length
 * @param output plaintext buffer
 * @param tag 16-byte authentication tag
 */
int aes_gcm_decrypt(unsigned char *key, unsigned char *iv,
                    unsigned char *input, size_t input_len,
                    unsigned char *output, unsigned char *tag);

/**
 * @brief Sign data using ECDSA + SHA256.
 * 
 * @param keypair private key (mbedtls_pk_context)
 * @param input data to sign
 * @param ilen length of input data
 * @param sig output signature buffer (at least 64 bytes)
 * @param sig_len pointer to receive signature length
 */
int ecdsa_sign(mbedtls_pk_context *keypair, unsigned char *input, size_t ilen,
               unsigned char *sig, size_t *sig_len);

/**
 * @brief Verify ECDSA signature with a public key point.
 * 
 * @param pubkey pointer to public mbedtls_ecp_point
 * @param input original message
 * @param ilen message length
 * @param sig signature
 * @param sig_len signature length
 */
int ecdsa_verify(mbedtls_ecp_point *pubkey, unsigned char *input, size_t ilen,
                 unsigned char *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_COMMON_H
