#include "cupqc_wrap.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <string.h>

typedef struct {
    OSSL_CUPQC_CTX *cupqc;
    unsigned char  *pub;   size_t publen;
    unsigned char  *priv;  size_t privlen;
    int mode; /* 1=encaps, 2=decaps */
} CUPQC_MLKEM_CTX;

static void *kem_newctx(void *provctx) {
    (void)provctx;
    CUPQC_MLKEM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->cupqc = ossl_cupqc_ctx_new();
    if (!ossl_cupqc_available(ctx->cupqc)) {
        ossl_cupqc_ctx_free(ctx->cupqc);
        OPENSSL_free(ctx);
        return NULL;
    }
    return ctx;
}

static void kem_freectx(void *vctx) {
    CUPQC_MLKEM_CTX *ctx = (CUPQC_MLKEM_CTX *)vctx;
    if (!ctx) return;
    ossl_cupqc_ctx_free(ctx->cupqc);
    OPENSSL_clear_free(ctx->pub, ctx->publen);
    OPENSSL_clear_free(ctx->priv, ctx->privlen);
    OPENSSL_free(ctx);
}

static int kem_encapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)vkey;
    CUPQC_MLKEM_CTX *ctx = (CUPQC_MLKEM_CTX *)vctx;
    if (!ctx || !ossl_cupqc_available(ctx->cupqc)) return 0;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    const unsigned char *pub = NULL; size_t publen = 0;
    if (!p || !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pub, &publen)) return 0;
    if (publen != ctx->cupqc->pk_len_768) return 0;

    OPENSSL_clear_free(ctx->pub, ctx->publen);
    ctx->pub = OPENSSL_memdup(pub, publen);
    ctx->publen = publen;
    ctx->mode = 1;
    return ctx->pub != NULL;
}

static int kem_encapsulate(void *vctx,
                           unsigned char *ct, size_t *ctlen,
                           unsigned char *ss, size_t *sslen) {
    CUPQC_MLKEM_CTX *ctx = (CUPQC_MLKEM_CTX *)vctx;
    if (!ctx || !ossl_cupqc_available(ctx->cupqc)) return 0;

    if (!ct || !ss) {
        if (ctlen) *ctlen = ctx->cupqc->ct_len_768;
        if (sslen) *sslen = ctx->cupqc->ss_len_768;
        return 1;
    }
    if (!ctlen || !sslen) return 0;
    if (*ctlen < ctx->cupqc->ct_len_768 || *sslen < ctx->cupqc->ss_len_768) return 0;
    if (!ctx->pub || ctx->publen != ctx->cupqc->pk_len_768) return 0;

    int rc = ctx->cupqc->mlkem768_encaps(ct, ss, ctx->pub);
    if (rc != 0) return 0;

    *ctlen = ctx->cupqc->ct_len_768;
    *sslen = ctx->cupqc->ss_len_768;
    return 1;
}

static int kem_decapsulate_init(void *vctx, void *vkey, const OSSL_PARAM params[]) {
    (void)vkey;
    CUPQC_MLKEM_CTX *ctx = (CUPQC_MLKEM_CTX *)vctx;
    if (!ctx || !ossl_cupqc_available(ctx->cupqc)) return 0;

    const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    const unsigned char *sk = NULL; size_t sklen = 0;
    if (!p || !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&sk, &sklen)) return 0;
    if (sklen != ctx->cupqc->sk_len_768) return 0;

    OPENSSL_clear_free(ctx->priv, ctx->privlen);
    ctx->priv = OPENSSL_memdup(sk, sklen);
    ctx->privlen = sklen;
    ctx->mode = 2;
    return ctx->priv != NULL;
}

static int kem_decapsulate(void *vctx,
                           unsigned char *ss, size_t *sslen,
                           const unsigned char *ct, size_t ctlen) {
    CUPQC_MLKEM_CTX *ctx = (CUPQC_MLKEM_CTX *)vctx;
    if (!ctx || !ossl_cupqc_available(ctx->cupqc)) return 0;

    if (!ss) { if (sslen) *sslen = ctx->cupqc->ss_len_768; return 1; }
    if (!sslen) return 0;
    if (ctlen != ctx->cupqc->ct_len_768) return 0;
    if (*sslen < ctx->cupqc->ss_len_768) return 0;
    if (!ctx->priv || ctx->privlen != ctx->cupqc->sk_len_768) return 0;

    int rc = ctx->cupqc->mlkem768_decaps(ss, ct, ctx->priv);
    if (rc != 0) return 0;

    *sslen = ctx->cupqc->ss_len_768;
    return 1;
}

static const OSSL_DISPATCH mlkem768_fns[] = {
    { OSSL_FUNC_KEM_NEWCTX,           (void (*)(void))kem_newctx },
    { OSSL_FUNC_KEM_FREECTX,          (void (*)(void))kem_freectx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE,      (void (*)(void))kem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE,      (void (*)(void))kem_decapsulate },
    { 0, NULL }
};

const OSSL_ALGORITHM ossl_cupqc_kem_algs[] = {
    { "ML-KEM-768:MLKEM768", "accelerated=gpu", mlkem768_fns },
    { NULL, NULL, NULL }
};
