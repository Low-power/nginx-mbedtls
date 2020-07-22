
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Yawning Angel <yawning at schwanenlied dot me>
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>


#define MBEDTLS_DN_MAX_LENGTH          256
#define MBEDTLS_SSL_CIPHER_MAX_LENGTH  64


static void ngx_ssl_handshake_handler(ngx_event_t *ev);
static ngx_int_t ngx_ssl_handle_recv(ngx_connection_t *c, int n);
static void ngx_ssl_write_handler(ngx_event_t *wev);
static void ngx_ssl_read_handler(ngx_event_t *rev);
static void ngx_ssl_shutdown_handler(ngx_event_t *ev);
static void ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
    ngx_slab_pool_t *shpool, ngx_uint_t n);
static void ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
static int ngx_polarssl_get_cache(void *ctx, struct mbedtls_ssl_session *session);
static int ngx_polarssl_set_cache(void *ctx, const struct mbedtls_ssl_session *session);
static void ngx_cdecl ngx_polarssl_error(ngx_uint_t level, ngx_log_t *log,
    ngx_err_t err, int sslerr, char *fmt, ...);
static int ngx_polarssl_cipher_in_list(const int id, const int *ciphersuites);
static ngx_int_t ngx_polarssl_set_cipher_list(ngx_ssl_t *ssl,
    const char *ciphers);
static const char *ngx_polarssl_verify_error_str(int n);
static int ngx_polarssl_rng(void *data, unsigned char *output, size_t output_len);
static void ngx_polarssl_exit(ngx_cycle_t *cycle);


static mbedtls_ctr_drbg_context ngx_ctr_drbg;
#if (NGX_THREADS)
static ngx_mutex *ngx_ctr_drbg_mutex;
#endif


static ngx_command_t  ngx_polarssl_commands[] = {
    ngx_null_command
};


static ngx_core_module_t  ngx_polarssl_module_ctx = {
    ngx_string("polarssl"),
    NULL,
    NULL
};


ngx_module_t  ngx_polarssl_module = {
    NGX_MODULE_V1,        
    &ngx_polarssl_module_ctx,           /* module context */
    ngx_polarssl_commands,              /* module directives */
    NGX_CORE_MODULE,                    /* module type */
    NULL,                               /* init master */
    NULL,                               /* init module */
    NULL,                               /* init process */
    NULL,                               /* init thread */
    NULL,                               /* exit thread */
    NULL,                               /* exit process */
    ngx_polarssl_exit,                  /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t
ngx_ssl_init(ngx_log_t *log)
{
    static const unsigned char ctr_drbg_custom[] = "nginx-mbedtls";
    mbedtls_entropy_context entropy;
    int e;

    /* Initialize the PRNG */

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ngx_ctr_drbg);
    e = mbedtls_ctr_drbg_seed(&ngx_ctr_drbg, mbedtls_entropy_func, &entropy,
                               ctr_drbg_custom, sizeof ctr_drbg_custom - 1);
    if(e) {
        ngx_polarssl_error(NGX_LOG_ERR, log, 0, e,
                           "mbedtls_ctr_drbg_seed failed");
        return NGX_ERROR;
    }

#if (NGX_THREADS)
    ngx_ctr_drbg_mutex = ngx_mutex_init(log, 0);
    if (ngx_ctr_drbg_mutex == NULL) {
        return NGX_ERROR;
    }
#endif

    return NGX_OK;
}


ngx_int_t
ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data)
{
    int  minor_min = 99;
    int  minor_max = -99;

    ssl->data = data;
    ssl->builtin_session_cache = NGX_SSL_NO_SCACHE;
    ssl->cache_shm_zone = NULL;

    /*
     * PolarSSL only allows the user to specify the minimum and* maximum
     * versions of SSL/TLS to support.
     */

    if (protocols & NGX_SSL_SSLv3) {
        minor_min = MBEDTLS_SSL_MINOR_VERSION_0;
        minor_max = MBEDTLS_SSL_MINOR_VERSION_0;
    }

    if (protocols & NGX_SSL_TLSv1) {
        minor_min = ngx_min(minor_min, MBEDTLS_SSL_MINOR_VERSION_1);
        minor_max = MBEDTLS_SSL_MINOR_VERSION_1;
    }

    if (protocols & NGX_SSL_TLSv1_1) {
        minor_min = ngx_min(minor_min, MBEDTLS_SSL_MINOR_VERSION_2);
        minor_max = MBEDTLS_SSL_MINOR_VERSION_2;
    }

    if (protocols & NGX_SSL_TLSv1_2) {
        minor_min = ngx_min(minor_min, MBEDTLS_SSL_MINOR_VERSION_3);
        minor_max = MBEDTLS_SSL_MINOR_VERSION_3;
    }

    ssl->minor_min = minor_min;
    ssl->minor_max = minor_max;

    /* Initialize the rest of the global state with sane defaults */

    ssl->ciphersuites = NULL;
    ngx_memset(&ssl->dhm_ctx, 0, sizeof(mbedtls_dhm_context));
    ngx_memset(&ssl->own_cert, 0, sizeof(mbedtls_x509_crt));
    ngx_memset(&ssl->own_key, 0, sizeof(mbedtls_pk_context));
    ngx_memset(&ssl->ca_cert, 0, sizeof(mbedtls_x509_crt));
    ngx_memset(&ssl->ca_crl, 0, sizeof(mbedtls_x509_crl));
    ssl->have_own_cert = 0;
    ssl->have_ca_cert = 0;
    ssl->have_ca_crl = 0;

    // To make the struct compatible with the OpenSSL version
    ssl->ctx = ssl;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_str_t *key)
{
    int  sslerr;

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    sslerr = mbedtls_x509_crt_parse_file(&ssl->own_cert, (char *) cert->data);
    if (sslerr != 0) {
        ngx_polarssl_error(NGX_LOG_EMERG, ssl->log, 0, sslerr,
                           "mbedtls_x509_crt_parse_file(%p, \"%s\") failed",
                           &ssl->own_cert, cert->data);
        return NGX_ERROR;
    }

    if (ngx_conf_full_name(cf->cycle, key, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    sslerr = mbedtls_pk_parse_keyfile(&ssl->own_key, (char *) key->data, NULL);
    if (sslerr != 0) {
        ngx_polarssl_error(NGX_LOG_EMERG, ssl->log, 0, sslerr,
                           "mbedtls_pk_parse_keyfile(%p, \"%s\", NULL) failed",
                           &ssl->own_key, key->data);
        return NGX_ERROR;
    }

    ssl->have_own_cert = 1;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    int  sslerr;

    if (cert->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    sslerr = mbedtls_x509_crt_parse_file(&ssl->ca_cert, (char *) cert->data);
    if (sslerr != 0) {
        ngx_polarssl_error(NGX_LOG_EMERG, ssl->log, 0, sslerr,
                           "mbedtls_x509_crt_parse_file(%p, \"%s\") failed",
                           &ssl->ca_cert, cert->data);
        return NGX_ERROR;
    }

    ssl->have_ca_cert = 1;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *cert,
    ngx_int_t depth)
{
    int  sslerr;

    if (cert->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, cert, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    /* Just add the certificate to the CA cert chain */

    sslerr = mbedtls_x509_crt_parse_file(&ssl->ca_cert, (char *) cert->data);
    if (sslerr != 0) {
        ngx_polarssl_error(NGX_LOG_EMERG, ssl->log, 0, sslerr,
                           "mbedtls_x509_crt_parse_file(%p, \"%s\") failed",
                           &ssl->ca_cert, cert->data);
        return NGX_ERROR;
    }

    ssl->have_ca_cert = 1;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl)
{
    int  sslerr;

    if (crl->len == 0) {
        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, crl, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    sslerr = mbedtls_x509_crl_parse_file(&ssl->ca_crl, (char *) crl->data);
    if (sslerr != 0) {
        ngx_polarssl_error(NGX_LOG_EMERG, ssl->log, 0, sslerr,
                           "mbedtls_x509_crl_parse_file(%p, \"%s\") failed",
                           &ssl->ca_crl, crl->data, sslerr);
        return NGX_ERROR;
    }

    ssl->have_ca_crl = 1;

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file,
    ngx_str_t *responder, ngx_uint_t verify)
{

    /* Not supported by PolarSSL */

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
        ngx_resolver_t *resolver, ngx_msec_t resolver_timeout)
{

    /* Not supported by PolarSSL */

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file)
{
    int  sslerr;

    static unsigned char dh1024_pem[] = {
        "-----BEGIN DH PARAMETERS-----\n"
        "MIGHAoGBALu8LcrYRnSQfEP89YDpz9vZWKP1aLQtSwju1OsPs1BMbAMCducQgAxc\n"
        "y7qokiYUxb7spWWl/fHSh6K8BJvmd4Bg6RqSp1fjBI9osHb302zI8pul34HcLKcl\n"
        "7OZicMyaUDXYzs7vnqAnSmOrHlj6/UmI0PZdFGdX2gcd8EXP4WubAgEC\n"
        "-----END DH PARAMETERS-----"
    };


    if (file->len == 0) {
        sslerr = mbedtls_dhm_parse_dhm(&ssl->dhm_ctx, dh1024_pem,
                               sizeof dh1024_pem);
        if (sslerr != 0) {
            ngx_polarssl_error(NGX_LOG_EMERG, ssl->log, 0, sslerr,
                               "mbedtls_dhm_parse_dhm() failed");

            return NGX_ERROR;
        }

        return NGX_OK;
    }

    if (ngx_conf_full_name(cf->cycle, file, 1) != NGX_OK) {
        return NGX_ERROR;
    }

    sslerr = mbedtls_dhm_parse_dhmfile(&ssl->dhm_ctx, (char *) file->data);
    if (sslerr != 0) {
        ngx_polarssl_error(NGX_LOG_EMERG, ssl->log, 0, sslerr,
                           "mbedtls_dhm_parse_dhmfile(%p, \"%s\") failed",
                           &ssl->dhm_ctx, file->data);

        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name)
{

    /* ECDH is not supported by PolarSSL */
    
    return NGX_OK;
}


ngx_int_t
ngx_ssl_cipher_list(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *ciphers)
{
    return ngx_polarssl_set_cipher_list(ssl, (const char *) ciphers->data);
}


void
ngx_ssl_sni_fn(ngx_ssl_t *ssl, int (*sni_fn)(void *, struct mbedtls_ssl_context *,
  const unsigned char *, size_t))
{
    ssl->sni_fn = sni_fn;
}


ngx_int_t
ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t timeout)
{

    /*
     * Setting up the session cache is done on a per connection basis
     * like everything else in PolarSSL, so save the user provided
     * setting till later, unless they want to use the builtin
     * cache.
     * 
     * If they want to use the builtin cache, log an error because
     * the builtin cache is not supported (and probably not worth
     * supporting since it is rather trivial, and the one that this
     * module provides is better within the context of ngnix).
     */

    if (builtin_session_cache == NGX_SSL_DFLT_BUILTIN_SCACHE) {
        ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                      "PolarSSL's builtin session cache is not supported.");
        return NGX_ERROR;
    }

    ssl->builtin_session_cache = builtin_session_cache;

    if (builtin_session_cache != NGX_SSL_NO_SCACHE) {
        ssl->cache_shm_zone = shm_zone;
        ssl->cache_ttl = timeout;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    size_t                    len;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_session_cache_t  *cache;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    if (shm_zone->shm.exists) {
        shm_zone->data = data;
        return NGX_OK;
    }

    /*
     * Much like ngx_event_openssl, we use a red-black tree and a queue as
     * the backing store for our cache.
     */

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    cache = ngx_slab_alloc(shpool, sizeof(ngx_ssl_session_cache_t));
    if (cache == NULL) {
        return NGX_ERROR;
    }
   
    shpool->data = cache; 
    shm_zone->data = cache;

    ngx_rbtree_init(&cache->session_rbtree, &cache->sentinel,
                    ngx_ssl_session_rbtree_insert_value);

    ngx_queue_init(&cache->expire_queue);

    len = sizeof(" in SSL session shared cache \"\"") + shm_zone->shm.name.len;

    shpool->log_ctx = ngx_slab_alloc(shpool, len);
    if (shpool->log_ctx == NULL) {
        return NGX_ERROR;
    }

    ngx_sprintf(shpool->log_ctx, " in SSL session shared cache \"%V\"%Z",
                &shm_zone->shm.name);

    return NGX_OK;
}

ngx_int_t
ngx_ssl_session_ticket_keys(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_array_t *paths)
{
    if (paths) {
        ngx_log_error(NGX_LOG_WARN, ssl->log, 0,
                      "\"ssl_session_ticket_keys\" ignored, not supported");
    }

    return NGX_OK;
}

void
ngx_ssl_remove_cached_session(ngx_ssl_t *ssl, ngx_ssl_session_t *sess)
{
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_session_cache_t  *cache;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_ssl_sess_id_t        *sess_id;
    int                       rc;
    uint32_t                  hash;

    shm_zone = ssl->cache_shm_zone;
    if (shm_zone == NULL) {
        return;
    }

    shpool = (ngx_slab_pool_t*) shm_zone->shm.addr;
    cache = shm_zone->data;

    hash = ngx_crc32_short(sess->id, sess->id_len);

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {
        
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (ngx_ssl_sess_id_t *) node;

        rc = ngx_memn2cmp(sess->id, sess_id->session->id, sess->id_len,
                node->data);

        if (rc == 0) {
            ngx_queue_remove(&sess_id->queue);

            ngx_rbtree_delete(&cache->session_rbtree, node);

            ngx_slab_free_locked(shpool, sess_id->session);

            ngx_slab_free_locked(shpool, sess_id);

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:
    ngx_shmtx_unlock(&shpool->mutex);
}


static int
ngx_polarssl_get_cache(void *ctx, struct mbedtls_ssl_session *session)
{
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_session_cache_t  *cache;
    ngx_rbtree_node_t        *node, *sentinel;
    ngx_ssl_sess_id_t        *sess_id;
    time_t                    expires;
    int                       rc;
    uint32_t                  hash;

    if (ctx == NULL) {
        /* NGX_SSL_NONE_SCACHE: Every search is a cache miss */
        return 1;
    }

    hash = ngx_crc32_short(session->id, session->id_len);

    shm_zone = ctx;
    shpool = (ngx_slab_pool_t*) shm_zone->shm.addr;
    cache = shm_zone->data;

    ngx_shmtx_lock(&shpool->mutex);

    node = cache->session_rbtree.root;
    sentinel = cache->session_rbtree.sentinel;

    while (node != sentinel) {
        
        if (hash < node->key) {
            node = node->left;
            continue;
        }

        if (hash > node->key) {
            node = node->right;
            continue;
        }

        /* hash == node->key */

        sess_id = (ngx_ssl_sess_id_t *) node;

        rc = ngx_memn2cmp(session->id, sess_id->session->id, session->id_len,
                node->data);

        if (rc == 0) {

            if (session->ciphersuite != sess_id->session->ciphersuite ||
                session->compression != sess_id->session->compression ||
                session->id_len != sess_id->session->id_len) {
                /* The ciphersuite/compression changed out from under us */
                goto done;
            }

            /* Check the expiry time */

            expires = (time_t) sess_id->session->peer_cert;
            if (expires > ngx_time()) {
                /* Cache hit */

                ngx_memcpy(session->master, sess_id->session->master, 48);

                ngx_shmtx_unlock(&shpool->mutex);

                return 0;
            }

            /* Cache entry expired */

            ngx_queue_remove(&sess_id->queue);

            ngx_rbtree_delete(&cache->session_rbtree, node);

            ngx_slab_free_locked(shpool, sess_id->session);

            ngx_slab_free_locked(shpool, sess_id);

            goto done;
        }

        node = (rc < 0) ? node->left : node->right;
    }

done:
    ngx_shmtx_unlock(&shpool->mutex);

    return 1;
}


static int
ngx_polarssl_set_cache(void *ctx, const struct mbedtls_ssl_session *session)
{
    ngx_shm_zone_t           *shm_zone;
    ngx_slab_pool_t          *shpool;
    ngx_ssl_session_cache_t  *cache;
    ngx_ssl_sess_id_t        *sess_id;
    ngx_ssl_session_t        *cached_sess;
    uint32_t                  hash;

    if (ctx == NULL) {
        /* NGX_SSL_NONE_SCACHE: Never cache any entries, but pretend to do so. */
        return 0;
    }

    shm_zone = ctx;
    shpool = (ngx_slab_pool_t*) shm_zone->shm.addr;
    cache = shm_zone->data;

    ngx_shmtx_lock(&shpool->mutex);

    /*
     * Because we need to store the entire ssl_session, in the cache we allocate
     * the entry and the ssl_session separately.  The entry is 64 bytes in size
     * on 64 bit architectures, and ssl_session is 112 bytes.
     *
     * Since we explicitly do not cache the peer certificate (requires a deep
     * copy), we hijack session.peer_cert and use that to store the expiration
     * time.  As far as I know sizeof(void *) == sizeof(time_t) is a reasonable
     * assumption to make.  This doesn't actually save anything on 64 bit
     * systems, but it *may* on 32 bit and it's not practical to break up a
     * ssl_session without being vulnerable to PolarSSL code changes.
     */

    /* Prune some sessions from the cache to ensure the allocation succeds */
    
    ngx_ssl_expire_sessions(cache, shpool, 1);

    cached_sess = ngx_slab_alloc_locked(shpool, sizeof(ngx_ssl_session_t));
    if (cached_sess == NULL) {

        /* Prune the oldest non-expired session, and try again */

        ngx_ssl_expire_sessions(cache, shpool, 0);

        cached_sess = ngx_slab_alloc_locked(shpool, sizeof(ngx_ssl_session_t));
        if (cached_sess == NULL) {
            goto failed;
        }
    }

    sess_id = ngx_slab_alloc_locked(shpool, sizeof(ngx_ssl_sess_id_t));
    if (sess_id == NULL) {
        goto failed;
    }

    memcpy(cached_sess, session, sizeof(ngx_ssl_session_t));
    cached_sess->peer_cert = (struct mbedtls_x509_crt *) (ngx_time() + cache->ttl);

    hash = ngx_crc32_short(cached_sess->id, cached_sess->id_len);

    sess_id->node.key = hash;
    sess_id->node.data = (u_char) cached_sess->id_len;
    sess_id->session = cached_sess;

    ngx_queue_insert_head(&cache->expire_queue, &sess_id->queue);

    ngx_rbtree_insert(&cache->session_rbtree, &sess_id->node);

    ngx_shmtx_unlock(&shpool->mutex);

    return 0;

failed:
    ngx_shmtx_unlock(&shpool->mutex);

    return 1;
}


static void
ngx_ssl_expire_sessions(ngx_ssl_session_cache_t *cache,
     ngx_slab_pool_t *shpool, ngx_uint_t n)
{
    time_t              now, then;
    ngx_queue_t        *q;
    ngx_ssl_sess_id_t  *sess_id;

    now = ngx_time();

    while (n < 3) {
        
        if (ngx_queue_empty(&cache->expire_queue)) {
            return;
        }

        q = ngx_queue_last(&cache->expire_queue);

        sess_id = ngx_queue_data(q, ngx_ssl_sess_id_t, queue);

        then = (time_t) sess_id->session->peer_cert;
        if (n++ != 0 && then > now) {
            return;
        }

        ngx_queue_remove(q);

        ngx_rbtree_delete(&cache->session_rbtree, &sess_id->node);

        ngx_slab_free_locked(shpool, sess_id->session);

        ngx_slab_free_locked(shpool, sess_id);
    }
}


static void
ngx_ssl_session_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel)
{
    ngx_rbtree_node_t  **p;
    ngx_ssl_sess_id_t   *sess_id, *sess_id_temp;

    for ( ;; ) {

        if (node->key < temp->key) {

            p = &temp->left;

        } else if (node->key > temp->key) {

            p = &temp->right;

        } else { /* node->key == temp->key */

            sess_id = (ngx_ssl_sess_id_t *) node;
            sess_id_temp = (ngx_ssl_sess_id_t *) temp;

            p = (ngx_memn2cmp(sess_id->session->id, sess_id_temp->session->id,
                              (size_t) node->data, (size_t) temp->data)
                 < 0) ? &temp->left : &temp->right;
        }

        if (*p == sentinel) {
            break;
        }

        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}


ngx_int_t
ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session)
{
    
    /*
     * TODO: ngx_http_upstream_round_robin uses this to set a SSL session to
     * allow session reuse.
     *
     * PolarSSL has ssl_set_session, but it does the copy on set.  The module
     * that actually uses this increments a refcount in ngx_ssl_get_session
     * instead so implementing this is requires more understanding of how
     * ngx_http_upstream_round_robin works.
     */

    return NGX_OK;
}


ngx_ssl_session_t*
ngx_ssl_get_session(ngx_connection_t *c)
{

    /* TODO: ngx_http_upstream_round_robin uses this to copy a SSL session */

    return NULL;
}


ngx_ssl_session_t *
ngx_ssl_peek_session(ngx_connection_t *c)
{
    return c->ssl->connection->session;
}


void
ngx_ssl_free_session(ngx_ssl_session_t *session)
{

    /* TODO: ngx_http_upstream_round_robin uses this to free a copied SSL session */
}


ngx_int_t
ngx_ssl_have_peer_cert(ngx_connection_t *c)
{
    if (mbedtls_ssl_get_peer_cert(c->ssl->connection) != NULL) {
        return NGX_OK;
    }

    return NGX_ERROR;
}


ngx_int_t
ngx_ssl_verify_result(ngx_connection_t *c, long *rc, const char **errstr)
{
    int  sslerr;

    sslerr = mbedtls_ssl_get_verify_result(c->ssl->connection);

    if (sslerr != 0) {
        *rc = sslerr;
        *errstr = ngx_polarssl_verify_error_str(sslerr);

        return NGX_ERROR;
    }

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->data = (u_char *) mbedtls_ssl_get_version(c->ssl->connection);
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    s->data = (u_char *) mbedtls_ssl_get_ciphersuite(c->ssl->connection);
    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    struct mbedtls_ssl_session  *session = c->ssl->connection->session;

    /*
     * ngx_event_openssl's implementation of this returns a hexdump of
     * the ASN.1 encoded SSL session object.  Our implementation just
     * returns a hexdump of the session id, because this routine is not
     * named ngx_ssl_get_entire_session_object.
     */

    s->len = session->id_len * 2;
    s->data = ngx_pnalloc(pool, s->len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(s->data, session->id, session->id_len);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    static const int            header_len = 29;
    static const int            footer_len = 25;
    static const unsigned char  pem_header[] = { "-----BEGIN CERTIFICATE-----\r\n" };
    static const unsigned char  pem_footer[] = { "-----END CERTIFICATE-----" };
    size_t                      len = 0, i;
    const struct mbedtls_x509_crt *cert;
    unsigned char              *p = NULL;

    /*
     * PolarSSL does not have a built in routine to write certificates
     * in PEM format.  Thankfully it's relatively easy to do since it
     * keeps a copy of the DER format certificate around.
     */

    cert = mbedtls_ssl_get_peer_cert(c->ssl->connection);
    if (cert == NULL || cert->raw.len == 0) {
        return NGX_OK;
    }

    /* Determine how much buffer space is required */

    mbedtls_base64_encode(NULL, 0, &len, cert->raw.p, cert->raw.len);
    len += (len / 64 + 1) * 2;
    len += header_len;
    len += footer_len;

    p = s->data = ngx_pnalloc(pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    /* Append the header */

    ngx_memcpy(p, pem_header, header_len);
    p += header_len;

    /* Base64 encode the cert, inserting newlines every 64 characters. */

    for (i = 0; i < cert->raw.len; /* i incremented in body */) {
        size_t to_encode = (cert->raw.len - i > 48) ? 48 : cert->raw.len - i;
        size_t dlen = len - (p - s->data);

        mbedtls_base64_encode(p, dlen, &dlen, cert->raw.p + i, to_encode);

        p += dlen;
        *p++ = '\r';
        *p++ = '\n';

        i+= to_encode;
    }

    /* Append the footer */

    ngx_memcpy(p, pem_footer, footer_len);
    p += footer_len;
    *p = '\0';

    s->len = ngx_strlen(s->data);

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{

    /*
     * As far as I can tell, both of ngx_ssl_get_certificate and
     * ngx_ssl_get_raw_certificate just return the peer certificate
     * in PEM format, with ngx_ssl_get_certificate messing with
     * whitespace.
     *
     * Since our PEM generator doesn't prefix any lines with whitespace
     * at all, the functions can just return identical output.
     */

    return ngx_ssl_get_raw_certificate(c, pool, s);
}


ngx_int_t
ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    const struct mbedtls_x509_crt *cert;
    int                            len;

    cert = mbedtls_ssl_get_peer_cert(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    s->data = ngx_pnalloc(pool, MBEDTLS_DN_MAX_LENGTH);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    len = mbedtls_x509_dn_gets((char *) s->data, MBEDTLS_DN_MAX_LENGTH - 1,
                            &cert->subject);
    if (len < 0) {
        return NGX_ERROR;
    }

    s->len = len;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    const struct mbedtls_x509_crt *cert;
    int                            len;

    cert = mbedtls_ssl_get_peer_cert(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    s->data = ngx_pnalloc(pool, MBEDTLS_DN_MAX_LENGTH);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    len = mbedtls_x509_dn_gets((char *) s->data, MBEDTLS_DN_MAX_LENGTH - 1,
                             &cert->issuer);
    if (len < 0) {
        return NGX_ERROR;
    }

    s->len = len;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    const struct mbedtls_x509_crt *cert;
    int               len;

    cert = mbedtls_ssl_get_peer_cert(c->ssl->connection);
    if (cert == NULL) {
        return NGX_OK;
    }

    len = cert->serial.len * 3 + 1;
    s->data = ngx_palloc(pool, len);
    if (s->data == NULL) {
        return NGX_ERROR;
    }

    len = mbedtls_x509_serial_gets((char *) s->data, len - 1, &cert->serial);
    if (len < 0) {
        return NGX_ERROR;
    }

    s->len = len;

    return NGX_OK;
}


ngx_int_t
ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool, ngx_str_t *s)
{
    const struct mbedtls_x509_crt  *cert;

    if (mbedtls_ssl_get_verify_result(c->ssl->connection) != 0) {
        ngx_str_set(s, "FAILED");
        return NGX_OK;
    }

    cert = mbedtls_ssl_get_peer_cert(c->ssl->connection);

    if (cert) {
        ngx_str_set(s, "SUCCESS");
    } else {
        ngx_str_set(s, "NONE");
    }

    return NGX_OK;
}


static int ngx_mbedtls_read(void *context, unsigned char *buffer, size_t length) {
	int fd = *(int *)context;
	int r = read(fd, buffer, length);
	if(r < 0) {
		int e = errno;
		switch(e) {
			case EAGAIN:
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
				if(fcntl(fd, F_GETFL) & (O_NONBLOCK
#ifdef O_NDELAY
					| O_NDELAY
#endif
				)) {
					return MBEDTLS_ERR_SSL_WANT_READ;
				}
				break;
			case EPIPE:
			case ECONNRESET:
				return MBEDTLS_ERR_NET_CONN_RESET;
			case EINTR:
				return MBEDTLS_ERR_SSL_WANT_READ;
		}
		errno = e;
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	return r;
}

static int ngx_mbedtls_write(void *context, const unsigned char *buffer, size_t length) {
	int fd = *(int *)context;
	int r = write(fd, buffer, length);
	if(r < 0) {
		int e = errno;
		switch(e) {
			case EAGAIN:
#if defined EWOULDBLOCK && EWOULDBLOCK != EAGAIN
			case EWOULDBLOCK:
#endif
				if(fcntl(fd, F_GETFL) & (O_NONBLOCK
#ifdef O_NDELAY
					| O_NDELAY
#endif
				)) {
					return MBEDTLS_ERR_SSL_WANT_WRITE;
				}
				break;
			case EPIPE:
			case ECONNRESET:
				return MBEDTLS_ERR_NET_CONN_RESET;
			case EINTR:
				return MBEDTLS_ERR_SSL_WANT_WRITE;
		}
		errno = e;
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	return r;
}



ngx_int_t
ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags)
{
    ngx_ssl_connection_t     *sc;
    ngx_ssl_conn_t           *ssl_ctx;
    ngx_ssl_session_cache_t  *cache;
    int                       sslerr;

    sc = ngx_pcalloc(c->pool, sizeof(ngx_ssl_connection_t));
    if (sc == NULL) {
        return NGX_ERROR;
    }

    sc->buffer = ((flags % NGX_SSL_BUFFER) != 0);

    /* Allocate the Mbed TLS config and context */

    sc->config = ngx_pcalloc(c->pool, sizeof(struct mbedtls_ssl_config));
    if (!sc->config) return NGX_ERROR;

    ssl_ctx = ngx_pcalloc(c->pool, sizeof(ngx_ssl_conn_t));
    if (sc == NULL) {
        ngx_pfree(c->pool, sc->config);
        return NGX_ERROR;
    }

    /*
     * Initialize this PolarSSL context
     *
     * Note: We also setup the options traditionally set in ngx_ssl_create
     * here since each ssl_ctx is unique to each fd.
     */

    mbedtls_ssl_config_init(sc->config);
    mbedtls_ssl_init(ssl_ctx);

    sslerr = mbedtls_ssl_config_defaults(sc->config,
                                         (flags & NGX_SSL_CLIENT) ? MBEDTLS_SSL_IS_CLIENT : MBEDTLS_SSL_IS_SERVER,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT);
    if (sslerr) {
        ngx_polarssl_error(NGX_LOG_ALERT, ssl->log, 0, sslerr,
                           "mbedtls_ssl_config_defaults failed");
        return NGX_ERROR;
    }

    if (flags & NGX_SSL_CLIENT) {
        if (ssl->have_own_cert) {
            mbedtls_ssl_conf_own_cert(sc->config, &ssl->own_cert, &ssl->own_key);
        }
    } else {
        mbedtls_ssl_conf_own_cert(sc->config, &ssl->own_cert, &ssl->own_key);
    }

    if (ssl->have_ca_cert) {
        if (ssl->have_ca_crl) {
            mbedtls_ssl_conf_ca_chain(sc->config, &ssl->ca_cert, &ssl->ca_crl);
        } else {
            mbedtls_ssl_conf_ca_chain(sc->config, &ssl->ca_cert, NULL);
        }

        /*
         * ngx_event_openssl has the callback rigged to allow the handshake
         * to continue even if verification fails.  We shall do the same.
         */

        mbedtls_ssl_conf_authmode(sc->config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    } else {
        mbedtls_ssl_conf_authmode(sc->config, MBEDTLS_SSL_VERIFY_NONE);
    }

    mbedtls_ssl_conf_min_version(sc->config, MBEDTLS_SSL_MAJOR_VERSION_3, ssl->minor_min);
    mbedtls_ssl_conf_max_version(sc->config, MBEDTLS_SSL_MAJOR_VERSION_3, ssl->minor_max);

    mbedtls_ssl_conf_renegotiation(sc->config, MBEDTLS_SSL_RENEGOTIATION_ENABLED);
    mbedtls_ssl_conf_legacy_renegotiation(sc->config, MBEDTLS_SSL_LEGACY_NO_RENEGOTIATION);

    mbedtls_ssl_conf_rng(sc->config, ngx_polarssl_rng, &ngx_ctr_drbg);
    mbedtls_ssl_set_bio(ssl_ctx, &c->fd, ngx_mbedtls_write, ngx_mbedtls_read, NULL);

    mbedtls_ssl_conf_dh_param_ctx(sc->config, &ssl->dhm_ctx);
    mbedtls_ssl_conf_ciphersuites(sc->config, ssl->ciphersuites);

    if (ssl->builtin_session_cache == NGX_SSL_NONE_SCACHE) {
        mbedtls_ssl_conf_session_cache(sc->config, NULL,
                ngx_polarssl_get_cache, ngx_polarssl_set_cache);
    }

    if (ssl->builtin_session_cache != NGX_SSL_NO_SCACHE && ssl->cache_shm_zone) {
        cache = ssl->cache_shm_zone->data;
        cache->ttl = ssl->cache_ttl;

        mbedtls_ssl_conf_session_cache(sc->config, ssl->cache_shm_zone,
                ngx_polarssl_get_cache, ngx_polarssl_set_cache);
    }

    if (ssl->sni_fn) {
        mbedtls_ssl_conf_sni(sc->config, ssl->sni_fn, c);
    }

    sslerr = mbedtls_ssl_setup(ssl_ctx, sc->config);
    if (sslerr) {
        ngx_polarssl_error(NGX_LOG_ALERT, ssl->log, 0, sslerr,
                           "mbedtls_ssl_setup failed");
        return NGX_ERROR;
    }

    /* All done, the connection is good to go now */

    sc->connection = ssl_ctx;
    c->ssl = sc;
    
    return NGX_OK;
}


ngx_int_t
ngx_ssl_handshake(ngx_connection_t *c)
{
    int  sslerr;

    sslerr = mbedtls_ssl_handshake(c->ssl->connection);

    if (sslerr == 0) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        c->ssl->handshaked = 1;

        c->recv = ngx_ssl_recv;
        c->send = ngx_ssl_write;
        c->recv_chain = ngx_ssl_recv_chain;
        c->send_chain = ngx_ssl_send_chain;

        /*
         * Versions of PolarSSL this is developed against are not vulnerable
         * to CVE-2009-3555, leave renegotiaton as is.
         */

        return NGX_OK;
    }

    if (sslerr == MBEDTLS_ERR_SSL_WANT_READ) {
        c->read->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    if (sslerr == MBEDTLS_ERR_SSL_WANT_WRITE) {
        c->write->ready = 0;
        c->read->handler = ngx_ssl_handshake_handler;
        c->write->handler = ngx_ssl_handshake_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_send_shutdown = 1;
    c->read->eof = 1;

    if (sslerr == MBEDTLS_ERR_SSL_CONN_EOF) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer closed connection in SSL handshake");
        return NGX_ERROR;
    }

    c->read->error = 1;

    ngx_polarssl_error(NGX_LOG_ERR, c->log, 0, sslerr, "mbedtls_ssl_handshake() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_handshake_handler(ngx_event_t *ev)
{
    ngx_connection_t  *c;

    c = ev->data;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "SSL handshake handler: %d", ev->write);

    if (ev->timedout) {
        c->ssl->handler(c);
        return;
    }

    if (ngx_ssl_handshake(c) == NGX_AGAIN) {
        return;
    }

    c->ssl->handler(c);
}


ssize_t
ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size)
{
    int  n, bytes;

    if (c->ssl->last == NGX_ERROR) {
        c->read->error = 1;
        return NGX_ERROR;
    }

    if (c->ssl->last == NGX_DONE) {
        c->read->ready = 0;
        c->read->eof = 1;
        return 0;
    }

    bytes = 0;

    for ( ;; ) {

        n = mbedtls_ssl_read(c->ssl->connection, buf, size);

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "ssl_read: %d", n);

        if (n > 0) {
            bytes += n;
        }

        c->ssl->last = ngx_ssl_handle_recv(c, n);

        if (c->ssl->last == NGX_OK) {
            size -= n;

            if (size == 0) {
                return bytes;
            }

            buf += n;

            continue;
        }

        if (bytes) {
            return bytes;
        }

        switch (c->ssl->last) {

        case NGX_DONE:
            c->read->ready = 0;
            c->read->eof = 1;
            return 0;

        case NGX_ERROR:
            c->read->error = 1;

            /* fall through */

        case NGX_AGAIN:
            return c->ssl->last;
        }
    }
}


static ngx_int_t
ngx_ssl_handle_recv(ngx_connection_t *c, int n)
{

    if (n > 0) {
        if (c->ssl->saved_write_handler) {
            c->write->handler = c->ssl->saved_write_handler;
            c->ssl->saved_write_handler = NULL;
            c->write->ready = 1;

            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->write, &ngx_posted_events);
        }

        return NGX_OK;
    }

    if (n == MBEDTLS_ERR_SSL_WANT_READ) {
        c->read->ready = 0;
        return NGX_AGAIN;
    }

    if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
        c->write->ready = 0;

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already the read event timer
         */

        if (c->ssl->saved_write_handler == NULL) {
            c->ssl->saved_write_handler = c->write->handler;
            c->write->handler = ngx_ssl_write_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_send_shutdown = 1;

    if (n == 0 || n == MBEDTLS_ERR_SSL_CONN_EOF ||
        n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, c->log, 0,
                       "peer shutdown SSL cleanly");
        return NGX_DONE;
    }

    ngx_polarssl_error(NGX_LOG_ERR, c->log, 0, n, "ssl_read() failed %d ", n);

    return NGX_ERROR;
}


static void
ngx_ssl_write_handler(ngx_event_t *wev)
{
    ngx_connection_t  *c;

    c = wev->data;

    c->read->handler(c->read);
}


ssize_t
ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size)
{
    int  n;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "SSL to write: %d", size);

    n = mbedtls_ssl_write(c->ssl->connection, data, size);

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0, "mbedtls_ssl_write: %d", n);

    if (n > 0) {

        if (c->ssl->saved_read_handler) {

            c->read->handler = c->ssl->saved_read_handler;
            c->ssl->saved_read_handler = NULL;
            c->read->ready = 1;

            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }

            ngx_post_event(c->read, &ngx_posted_events);
        }

        return n;
    }

    if (n == MBEDTLS_ERR_SSL_WANT_WRITE) {
        c->write->ready = 0;
        return NGX_AGAIN;
    }

    if (n == MBEDTLS_ERR_SSL_WANT_READ) {

        /* FIXME: Should this actually log?  It's handled fine. */

        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "peer started SSL renegotiation");

        c->read->ready = 0;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        /*
         * we do not set the timer because there is already
         * the write event timer
         */

        if (c->ssl->saved_read_handler == NULL) {
            c->ssl->saved_read_handler = c->read->handler;
            c->read->handler = ngx_ssl_read_handler;
        }

        return NGX_AGAIN;
    }

    c->ssl->no_send_shutdown = 1;
    c->write->error = 1;

    ngx_polarssl_error(NGX_LOG_ERR, c->log, 0, n, "ssl_write() failed");

    return NGX_ERROR;
}


static void
ngx_ssl_read_handler(ngx_event_t *rev)
{
    ngx_connection_t  *c;

    c = rev->data;

    c->write->handler(c->write);
}


ssize_t
ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl)
{
    u_char     *last;
    ssize_t     n, bytes;
    ngx_buf_t  *b;

    bytes = 0;

    b = cl->buf;
    last = b->last;

    for ( ;; ) {

        n = ngx_ssl_recv(c, last, b->end - last);

        if (n > 0) {
            last += n;
            bytes += n;

            if (last == b->end) {
                cl = cl->next;

                if (cl == NULL) {
                    return bytes;
                }

                b = cl->buf;
                last = b->last;
            }

            continue;
        }

        if (bytes) {
            if (n == 0 || n == NGX_ERROR) {
                c->read->ready = 1;
            }

            return bytes;
        }

        return n;
    }
}


ngx_chain_t *
ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in, off_t limit)
{
    int          n;
    ngx_uint_t   flush;
    ssize_t      send, size;
    ngx_buf_t   *buf;

    if (!c->ssl->buffer) {

        while (in) {
            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            n = ngx_ssl_write(c, in->buf->pos, in->buf->last - in->buf->pos);

            if (n == NGX_ERROR) {
                return NGX_CHAIN_ERROR;
            }

            if (n == NGX_AGAIN) {
                return in;
            }

            in->buf->pos += n;
            c->sent += n;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        return in;
    }

    /* the maximum limit size is the maximum int32_t value - the page size */

    if (limit == 0 || limit > (off_t) (NGX_MAX_INT32_VALUE - ngx_pagesize)) {
        limit = NGX_MAX_INT32_VALUE - ngx_pagesize;
    }

    buf = c->ssl->buf;

    if (buf == NULL) {
        buf = ngx_create_temp_buf(c->pool, NGX_SSL_BUFSIZE);
        if (buf == NULL) {
            return NGX_CHAIN_ERROR;
        }

        c->ssl->buf = buf;
    }

    send = buf->last - buf->pos;
    flush = (in == NULL) ? 1 : buf->flush;

    for ( ;; ) {

        while (in && buf->last < buf->end && send < limit) {
            if (in->buf->last_buf || in->buf->flush) {
                flush = 1;
            }

            if (ngx_buf_special(in->buf)) {
                in = in->next;
                continue;
            }

            size = in->buf->last - in->buf->pos;

            if (size > buf->end - buf->last) {
                size = buf->end - buf->last;
            }

            if (send + size > limit) {
                size = (ssize_t) (limit - send);
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                           "SSL buf copy: %d", size);

            ngx_memcpy(buf->last, in->buf->pos, size);

            buf->last += size;
            in->buf->pos += size;
            send += size;

            if (in->buf->pos == in->buf->last) {
                in = in->next;
            }
        }

        if (!flush && send < limit && buf->last < buf->end) {
            break;
        }

        size = buf->last - buf->pos;

        if (size == 0) {
            buf->flush = 0;
            c->buffered &= ~NGX_SSL_BUFFERED;
            return in;
        }

        n = ngx_ssl_write(c, buf->pos, size);

        if (n == NGX_ERROR) {
            return NGX_CHAIN_ERROR;
        }

        if (n == NGX_AGAIN) {
            break;
        }

        buf->pos += n;
        c->sent += n;

        if (n < size) {
            break;
        }

        flush = 0;

        buf->pos = buf->start;
        buf->last = buf->start;

        if (in == NULL || send == limit) {
            break;
        }
    }

    buf->flush = flush;

    if (buf->pos < buf->last) {
        c->buffered |= NGX_SSL_BUFFERED;

    } else {
        c->buffered &= ~NGX_SSL_BUFFERED;
    }

    return in;
}


void
ngx_ssl_free_buffer(ngx_connection_t *c)
{

    if (c->ssl->buf && c->ssl->buf->start) {
        if (ngx_pfree(c->pool, c->ssl->buf->start) == NGX_OK) {
            c->ssl->buf->start = NULL;
        }
    }
}


static void ngx_cdecl
ngx_polarssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, int sslerr,
    char *fmt, ...)
{
    va_list  args;
    u_char  *p, *last;
    u_char   errstr[NGX_MAX_CONF_ERRSTR];

    last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    p = ngx_vslprintf(errstr, last - 1, fmt, args);
    va_end(args);

    p = ngx_cpystrn(p, (u_char *) " (SSL:", last - p);
    mbedtls_strerror(sslerr, (char *) p, last - p);

    ngx_log_error(level, log, err, "%s", errstr);

}


void ngx_cdecl
ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, char *fmt, ...)
{
    va_list  args;
    // u_char  *p, *last;
    u_char   errstr[NGX_MAX_CONF_ERRSTR];

    // last = errstr + NGX_MAX_CONF_ERRSTR;

    va_start(args, fmt);
    // *p = ngx_vslprintf(errstr, last - 1, fmt, args);
    va_end(args);

    /*
     * PolarSSL does not have an error queue so it's not possible to access the
     * last error.  This doesn't really matter since this routine is not used
     * in PolarSSL builds.
     */

    ngx_log_error(level, log, err, "%s", errstr);
}


static void free_ssl_context(ngx_connection_t *c) {
	mbedtls_ssl_free(c->ssl->connection);
	ngx_pfree(c->pool, c->ssl->connection);
	ngx_pfree(c->pool, c->ssl->config);
	c->ssl = NULL;
}

ngx_int_t
ngx_ssl_shutdown(ngx_connection_t *c)
{
    int  sslerr;

    if (c->timedout || c->ssl->no_send_shutdown || c->ssl->no_wait_shutdown) {
        free_ssl_context(c);

        return NGX_OK;
    }

    sslerr = mbedtls_ssl_close_notify(c->ssl->connection);

    if (sslerr == 0 || sslerr == MBEDTLS_ERR_SSL_CONN_EOF) {
        free_ssl_context(c);

        return NGX_OK;
    }

    if (sslerr == MBEDTLS_ERR_SSL_WANT_READ ||
        sslerr == MBEDTLS_ERR_SSL_WANT_WRITE) {
        c->read->handler = ngx_ssl_shutdown_handler;
        c->write->handler = ngx_ssl_shutdown_handler;

        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
            return NGX_ERROR;
        }

        if (sslerr == MBEDTLS_ERR_SSL_WANT_READ) {
            ngx_add_timer(c->read, 300000);
        }

        return NGX_AGAIN;
    }
    
    ngx_polarssl_error(NGX_LOG_ERR, c->log, 0, sslerr,
                       "ssl_close_notify() failed");

    free_ssl_context(c);

    return NGX_ERROR;
}


static void
ngx_ssl_shutdown_handler(ngx_event_t *ev)
{
    ngx_connection_t           *c;
    ngx_connection_handler_pt   handler;

    c = ev->data;
    handler = c->ssl->handler;

    if (ev->timedout) {
        c->timedout = 1;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_EVENT, ev->log, 0, "SSL shutdown handler");

    if (ngx_ssl_shutdown(c) == NGX_AGAIN) {
        return;
    }

    handler(c);
}


void
ngx_ssl_cleanup_ctx(void *data)
{
    ngx_ssl_t  *ssl = data;

    if (ssl->ciphersuites != NULL) {
        ngx_free(ssl->ciphersuites);
    }

    mbedtls_dhm_free(&ssl->dhm_ctx);
    if (ssl->have_own_cert) {
        mbedtls_x509_crt_free(&ssl->own_cert);
        mbedtls_pk_free(&ssl->own_key);
    }
    if (ssl->have_ca_cert) {
        mbedtls_x509_crt_free(&ssl->ca_cert);
    }
    if (ssl->have_ca_crl) {
        mbedtls_x509_crl_free(&ssl->ca_crl);
    }
}


static int
ngx_polarssl_cipher_in_list(const int id, const int *ciphersuites)
{
    int  i;

    for (i = 0; ciphersuites[i] != 0; i++) {
        if (id == ciphersuites[i]) {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_polarssl_set_cipher_list(ngx_ssl_t *ssl, const char *ciphers)
{
    static const char   ngx_default_ciphers[] = "HIGH:!aNULL:!MD5";
    const int          *supported_ciphersuites;
    char                cipher_name[MBEDTLS_SSL_CIPHER_MAX_LENGTH];
    const char         *c, *end, *sep;
    int                 i, idx, cipher_id;

    /*
     * OpenSSL format cipher lists are somewhat nonsensical as the options
     * available under PolarSSL are somewhat more limited (most of the things a
     * user would chose to disable are flat out unsupported).
     *
     * Till someone can provide a really good reason otherwise, supporting the
     * nginx default (HIGH:!aNULL:!MD5) and allowing the user to pass in a
     * specific list should be sufficient.
     *
     * Note: We mimick the OpenSSL behavior of ignoring unknown entries,
     * mostly because the modules that call this don't bail out even if 0
     * is returned (total failure to configure ciphersuites should be
     * a fatal error at config time).
     */

    supported_ciphersuites = mbedtls_ssl_list_ciphersuites();
    for (i = 0; supported_ciphersuites[i] != 0; i++);

    ssl->ciphersuites = ngx_alloc((i + 1) * sizeof(int), ssl->log);
    if (ssl->ciphersuites == NULL) {
        return NGX_ERROR;
    }

    if (ngx_strcmp(ciphers, ngx_default_ciphers) == 0) {

        /* 
         * Special case for the default: "HIGH:!aNULL:!MD5":
         *
         * Just using the list from PolarSSL while probably reasonable does
         * not exclude options that are not included in "HIGH" and also will
         * (as a last resort) use TLS_RSA_RC4_128_MD5.
         */

        for (i = 0, idx = 0; supported_ciphersuites[idx] != 0; idx++) {

            switch (supported_ciphersuites[idx]) {
            /* aNULL ciphers - Never enabled by default, listed for clarity */
            case MBEDTLS_TLS_RSA_WITH_NULL_MD5:
            case MBEDTLS_TLS_RSA_WITH_NULL_SHA:
            case MBEDTLS_TLS_RSA_WITH_NULL_SHA256:

            /* MD5 ciphers */
            case MBEDTLS_TLS_RSA_WITH_RC4_128_MD5:

            /* Weak ciphers */
            case MBEDTLS_TLS_RSA_WITH_DES_CBC_SHA:
            case MBEDTLS_TLS_DHE_RSA_WITH_DES_CBC_SHA:
            case MBEDTLS_TLS_RSA_WITH_3DES_EDE_CBC_SHA:     /* Key size < 128 */
            case MBEDTLS_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA: /* Key size < 128 */
                continue;
                break;
            }

            ssl->ciphersuites[i] = supported_ciphersuites[idx];
            i++;
        }

        ssl->ciphersuites[i] = 0;

        return (i != 0) ? NGX_OK : NGX_ERROR;
    }

    /* Tokenize the list of ciphers */

    c = ciphers;
    i = 0;
    end = ciphers + ngx_strlen(ciphers);
    for (;;) {

        ssl->ciphersuites[i] = 0;

        sep = ngx_strchr(c, ':');
        if (sep == NULL) {
            sep = end;
        }

        /* FIXME: This is probably somewhat cryptic */

        if (sep - c > MBEDTLS_SSL_CIPHER_MAX_LENGTH) {
            ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                          "Out of buffer space when parsing cipher list: %s",
                          ciphers);
            goto skip;
        }

        ngx_memcpy(cipher_name, c, sep - c);
        cipher_name[sep - c] = '\0';

        cipher_id = mbedtls_ssl_get_ciphersuite_id(cipher_name);
        if (cipher_id == 0) {
            ngx_log_error(NGX_LOG_EMERG, ssl->log, 0,
                          "Unknown cipher requested: %s", cipher_name);
            goto skip;
        }

        /*
         * There are certain ciphers that can be enabled but will never
         * be returned in the list obtained by ssl_list_ciphersuites().
         *
         * While technically a PolarSSL bug, said ciphers are those that
         * no one in their right mind will ever enable, so just silently
         * ignore them (Not supporting the WEAK/NULL ciphers is a feature).
         *
         * Additionally, ensure that each cipher is only included once.
         */
        
        if (ngx_polarssl_cipher_in_list(cipher_id, supported_ciphersuites) &&
            !ngx_polarssl_cipher_in_list(cipher_id, ssl->ciphersuites)) {

            ssl->ciphersuites[i] = cipher_id;
            i++;
        }

skip:
        c = sep + 1;

        if (sep == end) {
            break;
        }
    }

    return (i != 0) ? NGX_OK : NGX_ERROR;
}


static const char *
ngx_polarssl_verify_error_str(int n)
{
    /*
     * n is a bit vector consisting of MBEDTLS_X509_BADCERT_EXPIRED, MBEDTLS_X509_BADCERT_REVOKED,
     * MBEDTLS_X509_BADCERT_CN_MISMATCH, MBEDTLS_X509_BADCERT_NOT_TRUSTED.
     */

    switch (n) {
    case MBEDTLS_X509_BADCERT_EXPIRED:
        return "Certificate expired";
    case MBEDTLS_X509_BADCERT_REVOKED:
        return "Certificate revoked";
    case MBEDTLS_X509_BADCERT_CN_MISMATCH:
        return "Certificate CN mismatch";
    case MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate not trusted";

    case MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_REVOKED:
        return "Certificate expired/revoked";
    case MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_CN_MISMATCH:
        return "Certificate expired/CN mismatch";
    case MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate expired/not trusted";
    case MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH:
        return "Certificate revoked/CN mismatch";
    case MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate revoked/not trusted";
    case MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate CN mismatch/not trusted";

    case MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH:
        return "Certificate expired/revoked/CN mismatch";
    case MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate expired/revoked/not trusted";
    case MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate expired/CN mismatch/not trusted";
    case MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH | MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate revoked/CN mismatch/not trusted";

    case MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_REVOKED | MBEDTLS_X509_BADCERT_CN_MISMATCH |
        MBEDTLS_X509_BADCERT_NOT_TRUSTED:
        return "Certificate expired/revoked/CN mismatch/not trusted";
    }

    return NULL;
}


static int
ngx_polarssl_rng(void *data, unsigned char *output, size_t output_len)
{
    int  rval;

#if (NGX_THREADS)
    ngx_mutex_lock(ngx_ctr_drbg_mutex);
#endif

    rval = mbedtls_ctr_drbg_random(data, output, output_len);

#if (NGX_THREADS)
    ngx_mutex_unlock(ngx_ctr_drbg_mutex);
#endif

    return rval;
}


static void
ngx_polarssl_exit(ngx_cycle_t *cycle)
{
#if (NGX_THREADS)
    ngx_mutex_destroy(ngx_ctr_drbg_mutex);
#endif
}

