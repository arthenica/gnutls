/*
 * This file was automatically generated from oqs.h,
 * which is covered by the following license:
 * SPDX-License-Identifier: MIT
 */
VOID_FUNC(void, OQS_init, (void), ())
VOID_FUNC(void, OQS_destroy, (void), ())
FUNC(const char *, OQS_version, (void), ())
VOID_FUNC(void, OQS_randombytes_custom_algorithm, (void (*algorithm_ptr)(uint8_t *, size_t)), (algorithm_ptr))
FUNC(int, OQS_KEM_alg_is_enabled, (const char *method_name), (method_name))
FUNC(OQS_KEM *, OQS_KEM_new, (const char *method_name), (method_name))
FUNC(OQS_STATUS, OQS_KEM_keypair, (const OQS_KEM *kem, uint8_t *public_key, uint8_t *secret_key), (kem, public_key, secret_key))
FUNC(OQS_STATUS, OQS_KEM_encaps, (const OQS_KEM *kem, uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key), (kem, ciphertext, shared_secret, public_key))
FUNC(OQS_STATUS, OQS_KEM_decaps, (const OQS_KEM *kem, uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key), (kem, shared_secret, ciphertext, secret_key))
VOID_FUNC(void, OQS_KEM_free, (OQS_KEM *kem), (kem))
VOID_FUNC(void, OQS_SHA2_set_callbacks, (struct OQS_SHA2_callbacks *new_callbacks), (new_callbacks))
VOID_FUNC(void, OQS_SHA3_set_callbacks, (struct OQS_SHA3_callbacks *new_callbacks), (new_callbacks))
VOID_FUNC(void, OQS_SHA3_x4_set_callbacks, (struct OQS_SHA3_x4_callbacks *new_callbacks), (new_callbacks))
FUNC(const char *, OQS_version, (void), ())
FUNC(OQS_SIG *, OQS_SIG_new, (const char *method_name), (method_name))
FUNC(OQS_STATUS, OQS_SIG_keypair, (const OQS_SIG* sig, uint8_t* public_key, uint8_t *secret_key), (sig, public_key, secret_key))
FUNC(OQS_STATUS, OQS_SIG_sign, (const OQS_SIG* sig, uint8_t *signature, size_t *signature_len, const uint8_t *message, size_t message_len, const uint8_t* secret_key), (sig, signature, signature_len, message, message_len, secret_key))
FUNC(OQS_STATUS, OQS_SIG_verify, (const OQS_SIG* sig, const uint8_t *message, size_t message_len, uint8_t *signature, size_t signature_len, const uint8_t* public_key), (sig, message, message_len, signature, signature_len, public_key))
VOID_FUNC(void, OQS_SIG_free, (OQS_SIG *sig), (sig))
