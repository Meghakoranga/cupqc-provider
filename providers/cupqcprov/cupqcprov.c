#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/crypto.h>
#include <string.h>

/* Implementations provided by this module */
extern const OSSL_ALGORITHM ossl_cupqc_kem_algs[];
extern const OSSL_ALGORITHM ossl_cupqc_km_algs[];

static const OSSL_PARAM prov_params_types[] = {
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_NAME, NULL, 0),
    OSSL_PARAM_utf8_ptr(OSSL_PROV_PARAM_VERSION, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *prov_gettable_params(void *provctx) {
    (void)provctx;
    return prov_params_types;
}

static int prov_get_params(void *provctx, OSSL_PARAM params[]) {
    (void)provctx;
    OSSL_PARAM *p = NULL;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "cupqcprov")) return 0;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p && !OSSL_PARAM_set_utf8_ptr(p, "0.3.0")) return 0;

    return 1;
}

static const OSSL_ALGORITHM *prov_query_operation(void *provctx, int op_id) {
    (void)provctx;
    switch (op_id) {
        case OSSL_OP_KEM:      return ossl_cupqc_kem_algs;
        case OSSL_OP_KEYMGMT:  return ossl_cupqc_km_algs;
        default:               return NULL;
    }
}

static const OSSL_DISPATCH cupqcprov_dispatch[] = {
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))prov_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,      (void (*)(void))prov_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))prov_query_operation },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **provctx) {
    (void)handle;
    (void)in;
    *provctx = NULL;
    *out = cupqcprov_dispatch;
    return 1;
}
