#include "crypto_common.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/gcm.h"
#include <string.h>
#include "esp_system.h"
#include "esp_random.h"


// -----------------------------------------------------------------------------
// Helper: RNG
// -----------------------------------------------------------------------------
static int init_rng(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy)
{
    //unique DRBG instance
    const char *pers = "rng_seed";
    mbedtls_entropy_init(entropy);
    mbedtls_ctr_drbg_init(ctr_drbg);
    //seed DRBG using entropy - zero successful
    return mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,(const unsigned char *)pers, strlen(pers));
}

// -----------------------------------------------------------------------------
// ECC keypair generation
// -----------------------------------------------------------------------------
int generate_ec_keypair(mbedtls_pk_context *keypair)
{
    int ret;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    mbedtls_pk_init(keypair);
    //PK context for an EC keypair
    if ((ret = mbedtls_pk_setup(keypair,
            mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))) != 0)
        return ret;
    //random number generator
    if ((ret = init_rng(&ctr_drbg, &entropy)) != 0)
        return ret;
    //Generate an EC keypair using the P-256
    ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1,
                              mbedtls_pk_ec(*keypair),
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    //free
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// -----------------------------------------------------------------------------
// ECDH shared secret
// -----------------------------------------------------------------------------
int compute_shared_secret(mbedtls_pk_context *private_key, mbedtls_ecp_point *peer_public, unsigned char *secret, size_t *secret_len)
{
    int ret = 0;
    mbedtls_ecdh_context ecdh;
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    init_rng(&ctr_drbg, &entropy);

    const mbedtls_ecp_keypair *our_key = mbedtls_pk_ec(*private_key);

    // 1. Setup ECDH with the same curve
    ret = mbedtls_ecdh_setup(&ecdh, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup;

    // 2. Load our private key into the ECDH context
    ret = mbedtls_ecdh_get_params(&ecdh, our_key, MBEDTLS_ECDH_OURS);
    if (ret != 0) goto cleanup;

    // 3. Create a temporary keypair for the peer’s public point
    mbedtls_ecp_keypair peer_key;
    mbedtls_ecp_keypair_init(&peer_key);
    ret = mbedtls_ecp_group_load(&peer_key.MBEDTLS_PRIVATE(grp),
                                 MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) goto cleanup_peer;

    // Copy peer public point into peer_key
    ret = mbedtls_ecp_copy(&peer_key.MBEDTLS_PRIVATE(Q), peer_public);
    if (ret != 0) goto cleanup_peer;

    // 4. Load peer public key into the ECDH context
    ret = mbedtls_ecdh_get_params(&ecdh, &peer_key, MBEDTLS_ECDH_THEIRS);
    if (ret != 0) goto cleanup_peer;

    // 5. Compute the shared secret
    ret = mbedtls_ecdh_calc_secret(&ecdh, secret_len, secret, 64, mbedtls_ctr_drbg_random, &ctr_drbg);

cleanup_peer:
    mbedtls_ecp_keypair_free(&peer_key);
cleanup:
    mbedtls_ecdh_free(&ecdh);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}



// -----------------------------------------------------------------------------
// SHA-256 based KDF
// -----------------------------------------------------------------------------
int kdf_sha256(unsigned char *input, size_t input_len, unsigned char *output, size_t output_len)
{
    unsigned char hash[32];//buffer
    //initialize digest
    mbedtls_md_context_t ctx;
    mbedtls_md_init(&ctx);
    //set SHA256
    mbedtls_md_setup(&ctx,mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 0);
    //hash
    mbedtls_md_starts(&ctx);
    mbedtls_md_update(&ctx, input, input_len);//hash inputdata
    mbedtls_md_finish(&ctx, hash);
    //free digest
    mbedtls_md_free(&ctx);
    //copy to output / max 32 bytes
    memcpy(output, hash, output_len > 32 ? 32 : output_len);
    return 0;
}

// -----------------------------------------------------------------------------
// AES-GCM encrypt/decrypt
// -----------------------------------------------------------------------------

int generate_random_iv(unsigned char *iv, size_t iv_len)
{
    if (!iv || iv_len == 0) return -1;
    //cycle through until full
    for (size_t i = 0; i < iv_len; i += 4) {
        uint32_t r = esp_random();
        size_t chunk = (iv_len - i >= 4) ? 4 : (iv_len - i);
        memcpy(iv + i, &r, chunk);
    }
    return 0;
}


int aes_gcm_encrypt(unsigned char *key, unsigned char *iv, unsigned char *input, size_t input_len, unsigned char *output, unsigned char *tag)
{
    int ret;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    //set AES key
    if ((ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, AES_KEY_SIZE * 8)) != 0) return ret;

    //Set GCM encryption
    ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT,input_len, iv, AES_IV_SIZE,NULL, 0, input, output,AES_TAG_SIZE, tag);
    
    //free context
    mbedtls_gcm_free(&gcm);
    return ret;
}

int aes_gcm_decrypt(unsigned char *key, unsigned char *iv, unsigned char *input, size_t input_len, unsigned char *output, unsigned char *tag)
{
    int ret;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    // set AES Key
    if ((ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES,
                                  key, AES_KEY_SIZE * 8)) != 0)
        return ret;
    // perform AES authenticated decryption
    ret = mbedtls_gcm_auth_decrypt(&gcm, input_len,
                                   iv, AES_IV_SIZE, NULL, 0,
                                   tag, AES_TAG_SIZE,
                                   input, output);
    //free GCM Context
    mbedtls_gcm_free(&gcm);
    return ret;
}

// -----------------------------------------------------------------------------
// ECDSA sign/verify
// -----------------------------------------------------------------------------
int ecdsa_sign(mbedtls_pk_context *keypair, unsigned char *input, size_t ilen, unsigned char *sig, size_t *sig_len)
{
    int ret;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    //initialize random ECDSA signing
    init_rng(&ctr_drbg, &entropy);

    mbedtls_ecdsa_context ctx_sign;
    mbedtls_ecdsa_init(&ctx_sign);
    // Extract EC keypair
    const mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*keypair);

    // Copy curve parameters
    mbedtls_ecp_group_copy(&ctx_sign.MBEDTLS_PRIVATE(grp),
                           &ec->MBEDTLS_PRIVATE(grp));
    mbedtls_mpi_copy(&ctx_sign.MBEDTLS_PRIVATE(d),
                     &ec->MBEDTLS_PRIVATE(d));
    mbedtls_ecp_copy(&ctx_sign.MBEDTLS_PRIVATE(Q),
                     &ec->MBEDTLS_PRIVATE(Q));

    // Provide buffer size and retrieve signature length separately
    ret = mbedtls_ecdsa_write_signature(&ctx_sign, MBEDTLS_MD_SHA256,
                                        input, ilen,
                                        sig, 64,  // sig buffer size
                                        sig_len,
                                        mbedtls_ctr_drbg_random, &ctr_drbg);

    //cleanup
    mbedtls_ecdsa_free(&ctx_sign);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int ecdsa_verify(mbedtls_ecp_point *pubkey, unsigned char *input, size_t ilen, unsigned char *sig, size_t sig_len)
{
    int ret;
    //Initialize verification context
    mbedtls_ecdsa_context verify_ctx;
    mbedtls_ecdsa_init(&verify_ctx);
    //load Curve parameters
    mbedtls_ecp_group_load(&verify_ctx.MBEDTLS_PRIVATE(grp),MBEDTLS_ECP_DP_SECP256R1);
    // set public key
    mbedtls_ecp_copy(&verify_ctx.MBEDTLS_PRIVATE(Q), pubkey);

    //verify signature
    ret = mbedtls_ecdsa_read_signature(&verify_ctx,input, ilen, sig, sig_len);
    mbedtls_ecdsa_free(&verify_ctx);
    return ret;
}
