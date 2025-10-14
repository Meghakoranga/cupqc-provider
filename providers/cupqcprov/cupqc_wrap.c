#include "cupqc_wrap.h"
#include <openssl/crypto.h>
#include <dlfcn.h>

static int resolve(void *h, const char *name, void **out) {
    void *p = dlsym(h, name);
    if (!p) return 0;
    *out = p;
    return 1;
}

OSSL_CUPQC_CTX *ossl_cupqc_ctx_new(void) {
    OSSL_CUPQC_CTX *c = OPENSSL_zalloc(sizeof(*c));
    if (!c) return NULL;

    c->handle = dlopen("libcupqc.so", RTLD_NOW | RTLD_LOCAL);
    if (!c->handle) {
        c->available = 0;
        return c;
    }

    int ok = 1;
    ok &= resolve(c->handle, "cupqc_mlkem768_keypair", (void **)&c->mlkem768_keypair);
    ok &= resolve(c->handle, "cupqc_mlkem768_encaps",  (void **)&c->mlkem768_encaps);
    ok &= resolve(c->handle, "cupqc_mlkem768_decaps",  (void **)&c->mlkem768_decaps);

    c->pk_len_768 = 1184;
    c->sk_len_768 = 2400;
    c->ct_len_768 = 1088;
    c->ss_len_768 = 32;

    c->available = ok ? 1 : 0;
    if (!c->available) {
        dlclose(c->handle);
        c->handle = NULL;
    }
    return c;
}

void ossl_cupqc_ctx_free(OSSL_CUPQC_CTX *c) {
    if (!c) return;
    if (c->handle) dlclose(c->handle);
    OPENSSL_free(c);
}

int ossl_cupqc_available(const OSSL_CUPQC_CTX *c) {
    return c && c->available;
}
