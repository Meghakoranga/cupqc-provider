#include "cupqc_wrap.h"
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/param_build.h>
#include <string.h>

typedef struct {
    OSSL_CUPQC_CTX *cupqc;
    unsigned char  *pub;  size_t publen;
    unsigned char  *priv; size_t privlen;
} CUPQC_MLKEM_KEY;

static void *km_new(void *provctx) {
    (void)provctx;
    CUPQC_MLKEM_KEY *k = OPENSSL_zalloc(sizeof(*k));
    if (!k) return NULL;
    k->cupqc = ossl_cupqc_ctx_new();
    if (!ossl_cupqc_available(k->cupqc)) {
        ossl_cupqc_ctx_free(k->cupqc);
        OPENSSL_free(k);
        return NULL;
    }
    return k;
}

static void km_free(void *keydata) {
    CUPQC_MLKEM_KEY *k = (CUPQC_MLKEM_KEY *)keydata;
    if (!k) return;
    ossl_cupqc_ctx_free(k->cupqc);
    OPENSSL_clear_free(k->pub, k->publen);
    OPENSSL_clear_free(k->priv, k->privlen);
    OPENSSL_free(k);
}

static int km_has(void *keydata, int selection) {
    CUPQC_MLKEM_KEY *k = (CUPQC_MLKEM_KEY *)keydata;
    if (!k) return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  && !k->pub)  return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !k->priv) return 0;
    return 1;
}

/* Advertise supported key parameters for import/export */
static const OSSL_PARAM *km_import_types(int selection) {
    static const OSSL_PARAM both[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };
    static const OSSL_PARAM pub_only[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,  NULL, 0),
        OSSL_PARAM_END
    };
    static const OSSL_PARAM priv_only[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    if (selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        return both;
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return priv_only;
    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        return pub_only;
    return NULL;
}

static const OSSL_PARAM *km_export_types(int selection) {
    /* Same sets as import_types for raw-octet keys */
    return km_import_types(selection);
}

static int km_import(void *keydata, int selection, const OSSL_PARAM params[]) {
    CUPQC_MLKEM_KEY *k = (CUPQC_MLKEM_KEY *)keydata;
    if (!k || !ossl_cupqc_available(k->cupqc)) return 0;

    if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) {
        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
        const unsigned char *pub = NULL; size_t publen = 0;
        if (!p || !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&pub, &publen)) return 0;
        if (publen != k->cupqc->pk_len_768) return 0;
        OPENSSL_clear_free(k->pub, k->publen);
        k->pub = OPENSSL_memdup(pub, publen); k->publen = publen;
        if (!k->pub) return 0;
    }
    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        const OSSL_PARAM *p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
        const unsigned char *sk = NULL; size_t sklen = 0;
        if (!p || !OSSL_PARAM_get_octet_string_ptr(p, (const void **)&sk, &sklen)) return 0;
        if (sklen != k->cupqc->sk_len_768) return 0;
        OPENSSL_clear_free(k->priv, k->privlen);
        k->priv = OPENSSL_memdup(sk, sklen); k->privlen = sklen;
        if (!k->priv) return 0;
    }
    return 1;
}

static int km_export(void *keydata, int selection, OSSL_CALLBACK *cb, void *cbarg) {
    CUPQC_MLKEM_KEY *k = (CUPQC_MLKEM_KEY *)keydata;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new(); if (!bld) return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)  && k->pub)
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, k->pub, k->publen)) goto err;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && k->priv)
        if (!OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, k->priv, k->privlen)) goto err;

    OSSL_PARAM *ps = OSSL_PARAM_BLD_to_param(bld);
    if (!ps) goto err;
    int ok = cb(ps, cbarg);
    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(bld);
    return ok;
err:
    OSSL_PARAM_BLD_free(bld);
    return 0;
}

/* Simple generator: produce raw octets via cuPQC keypair */
typedef struct { OSSL_CUPQC_CTX *cupqc; } KM_GEN_CTX;

static int km_gen_init(void *provctx, void **genctx) {
    (void)provctx;
    OSSL_CUPQC_CTX *c = ossl_cupqc_ctx_new();
    if (!ossl_cupqc_available(c)) { ossl_cupqc_ctx_free(c); return 0; }
    KM_GEN_CTX *g = OPENSSL_zalloc(sizeof(*g));
    if (!g) { ossl_cupqc_ctx_free(c); return 0; }
    g->cupqc = c;
    *genctx = g;
    return 1;
}

static int km_gen(void *genctx, OSSL_CALLBACK *cb, void *cbarg) {
    KM_GEN_CTX *g = (KM_GEN_CTX *)genctx;
    size_t pklen = g->cupqc->pk_len_768, sklen = g->cupqc->sk_len_768;
    unsigned char *pk = OPENSSL_malloc(pklen), *sk = OPENSSL_malloc(sklen);
    if (!pk || !sk) { OPENSSL_free(pk); OPENSSL_free(sk); return 0; }
    if (g->cupqc->mlkem768_keypair(pk, sk) != 0) { OPENSSL_free(pk); OPENSSL_free(sk); return 0; }

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new(); if (!bld) { OPENSSL_free(pk); OPENSSL_free(sk); return 0; }
    int ok = 1;
    ok &= OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,  pk, pklen);
    ok &= OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY, sk, sklen);

    OSSL_PARAM *ps = ok ? OSSL_PARAM_BLD_to_param(bld) : NULL;
    if (!ps) ok = 0;
    if (ok) ok = cb(ps, cbarg);

    OSSL_PARAM_free(ps);
    OSSL_PARAM_BLD_free(bld);
    OPENSSL_free(pk); OPENSSL_free(sk);
    return ok;
}

static void km_gen_cleanup(void *genctx) {
    KM_GEN_CTX *g = (KM_GEN_CTX *)genctx;
    if (!g) return;
    ossl_cupqc_ctx_free(g->cupqc);
    OPENSSL_free(g);
}

static const char *km_query_operation_name(int op) {
    return (op == OSSL_OP_KEM) ? "ML-KEM-768" : NULL;
}



static const OSSL_DISPATCH keymgmt_fns[] = {
    { OSSL_FUNC_KEYMGMT_NEW,                  (void (*)(void))km_new },
    { OSSL_FUNC_KEYMGMT_FREE,                 (void (*)(void))km_free },
    { OSSL_FUNC_KEYMGMT_HAS,                  (void (*)(void))km_has },
    { OSSL_FUNC_KEYMGMT_IMPORT,               (void (*)(void))km_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES,         (void (*)(void))km_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT,               (void (*)(void))km_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES,         (void (*)(void))km_export_types },
    { OSSL_FUNC_KEYMGMT_GEN_INIT,             (void (*)(void))km_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN,                  (void (*)(void))km_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP,          (void (*)(void))km_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME, (void (*)(void))km_query_operation_name },
    { 0, NULL }
};

const OSSL_ALGORITHM ossl_cupqc_km_algs[] = {
    { "ML-KEM-768:MLKEM768", "accelerated=gpu", keymgmt_fns },
    { NULL, NULL, NULL }
};
