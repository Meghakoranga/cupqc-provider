#ifndef OSSL_CUPQC_WRAP_H
#define OSSL_CUPQC_WRAP_H

#include <openssl/e_os2.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <stddef.h>
#include <stdint.h>

/* Runtime cuPQC context resolved with dlopen/dlsym */
typedef struct ossl_cupqc_ctx_st {
    void *handle;        /* dlopen("libcupqc.so") */
    int available;       /* 1 if symbols resolved */

    /* ML-KEM-768 sizes (replace with SDK queries later if available) */
    size_t pk_len_768;   /* 1184 */
    size_t sk_len_768;   /* 2400 */
    size_t ct_len_768;   /* 1088 */
    size_t ss_len_768;   /* 32   */

    /* cuPQC entry points (adjust names/signatures on GPU VM) */
    int (*mlkem768_keypair)(uint8_t *pk, uint8_t *sk);
    int (*mlkem768_encaps)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
    int (*mlkem768_decaps)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
} OSSL_CUPQC_CTX;

/* Lifetime */
OSSL_CUPQC_CTX *ossl_cupqc_ctx_new(void);
void ossl_cupqc_ctx_free(OSSL_CUPQC_CTX *c);
int ossl_cupqc_available(const OSSL_CUPQC_CTX *c);

#endif /* OSSL_CUPQC_WRAP_H */
