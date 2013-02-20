
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 * Copyright (C) Yawning Angel <yawning at schwanenlied dot me>
 */

#ifndef _NGX_EVENT_POLARSSL_H_INCLUDED_
#define _NGX_EVENT_POLARSSL_H_INCLUDED_

#include <ngx_config.h>
#include <ngx_core.h>

#include "polarssl/config.h"

#include "polarssl/base64.h"
#include "polarssl/entropy.h"
#include "polarssl/ctr_drbg.h"
#include "polarssl/net.h"
#include "polarssl/ssl.h"
#include "polarssl/certs.h"
#include "polarssl/x509.h"
#include "polarssl/error.h"

#define NGX_SSL_NAME    "PolarSSL"

#define ngx_ssl_session_t ssl_session
#define ngx_ssl_conn_t ssl_context

#define RSA rsa_context
#define SSL ssl_context

typedef struct {
    ngx_log_t       *log;
    void            *data;

    ssize_t         builtin_session_cache;
    ngx_shm_zone_t  *cache_shm_zone;
    time_t          cache_ttl;

    ngx_uint_t      minor_min;
    ngx_uint_t      minor_max;

    int             *ciphersuites;
    dhm_context     dhm_ctx;
    x509_cert       own_cert;
    rsa_context     own_key;
    x509_cert       ca_cert;
    x509_crl        ca_crl;

    unsigned        have_own_cert:1;
    unsigned        have_ca_cert:1;
    unsigned        have_ca_crl:1;

    /*
     * HACK: ngx_http_ssl_module expects to be able to get at the OpenSSL
     * ctx.  Eventually this should be better abstracted so this is not
     * needed.
     */
    void            *ctx;
} ngx_ssl_t;

typedef struct {
    ngx_ssl_conn_t              *connection;

    ngx_int_t                   last;
    ngx_buf_t                   *buf;

    ngx_connection_handler_pt   handler;

    ngx_event_handler_pt        saved_read_handler;
    ngx_event_handler_pt        saved_write_handler;

    unsigned                    handshaked:1;
    unsigned                    buffer:1;
    unsigned                    no_send_shutdown:1;
    unsigned                    no_wait_shutdown:1;
} ngx_ssl_connection_t;

typedef struct ngx_ssl_sess_id_s ngx_ssl_sess_id_t;

struct ngx_ssl_sess_id_s {
    ngx_rbtree_node_t           node;
    ngx_queue_t                 queue;
    ngx_ssl_session_t          *session;
};

typedef struct {
    ngx_rbtree_t                session_rbtree;
    ngx_rbtree_node_t           sentinel;
    ngx_queue_t                 expire_queue;
    time_t                      ttl;
} ngx_ssl_session_cache_t;


#define NGX_SSL_NO_SCACHE            -2
#define NGX_SSL_NONE_SCACHE          -3
#define NGX_SSL_NO_BUILTIN_SCACHE    -4
#define NGX_SSL_DFLT_BUILTIN_SCACHE  -5

#define NGX_SSL_SSLv2       0x0002
#define NGX_SSL_SSLv3       0x0004
#define NGX_SSL_TLSv1       0x0008
#define NGX_SSL_TLSv1_1     0x0010
#define NGX_SSL_TLSv1_2     0x0020

#define NGX_SSL_BUFFER      1
#define NGX_SSL_CLIENT      2

#define NGX_SSL_BUFSIZE     16384


ngx_int_t ngx_ssl_init(ngx_log_t *log);
ngx_int_t ngx_ssl_create(ngx_ssl_t *ssl, ngx_uint_t protocols, void *data);

ngx_int_t ngx_ssl_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_str_t *key);
ngx_int_t ngx_ssl_client_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_trusted_certificate(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *cert, ngx_int_t depth);
ngx_int_t ngx_ssl_crl(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *crl);
ngx_int_t ngx_ssl_stapling(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_str_t *file, ngx_str_t *responder, ngx_uint_t verify);
ngx_int_t ngx_ssl_stapling_resolver(ngx_conf_t *cf, ngx_ssl_t *ssl,
    ngx_resolver_t *resolver, ngx_msec_t resolver_timeout);
RSA *ngx_ssl_rsa512_key_callback(SSL *ssl, int is_export, int key_length);
ngx_int_t ngx_ssl_dhparam(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *file);
ngx_int_t ngx_ssl_ecdh_curve(ngx_conf_t *cf, ngx_ssl_t *ssl, ngx_str_t *name);

ngx_int_t ngx_ssl_session_cache(ngx_ssl_t *ssl, ngx_str_t *sess_ctx,
    ssize_t builtin_session_cache, ngx_shm_zone_t *shm_zone, time_t
    timeout);
ngx_int_t ngx_ssl_session_cache_init(ngx_shm_zone_t *shm_zone, void *data);
void ngx_ssl_remove_cached_session(ngx_ssl_t *ssl, ngx_ssl_session_t *sess);
ngx_int_t ngx_ssl_set_session(ngx_connection_t *c, ngx_ssl_session_t *session);
ngx_ssl_session_t *ngx_ssl_get_session(ngx_connection_t *c);
void ngx_ssl_free_session(ngx_ssl_session_t *session);
/* ngx_connection_t *ngx_ssl_get_connection(ngx_ssl_conn_t *ssl_conn); */

ngx_int_t ngx_ssl_verify_error_optional(int n);

ngx_int_t ngx_ssl_get_protocol(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_cipher_name(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_session_id(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_raw_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_certificate(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_subject_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_issuer_dn(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_serial_number(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);
ngx_int_t ngx_ssl_get_client_verify(ngx_connection_t *c, ngx_pool_t *pool,
    ngx_str_t *s);

ngx_int_t ngx_ssl_create_connection(ngx_ssl_t *ssl, ngx_connection_t *c,
    ngx_uint_t flags);
ngx_int_t ngx_ssl_handshake(ngx_connection_t *c);
ssize_t ngx_ssl_recv(ngx_connection_t *c, u_char *buf, size_t size);
ssize_t ngx_ssl_write(ngx_connection_t *c, u_char *data, size_t size);
ssize_t ngx_ssl_recv_chain(ngx_connection_t *c, ngx_chain_t *cl);
ngx_chain_t *ngx_ssl_send_chain(ngx_connection_t *c, ngx_chain_t *in,
    off_t limit);
void ngx_ssl_free_buffer(ngx_connection_t *c);
ngx_int_t ngx_ssl_shutdown(ngx_connection_t *c);
void ngx_cdecl ngx_ssl_error(ngx_uint_t level, ngx_log_t *log, ngx_err_t err,
    char *fmt, ...);
void ngx_ssl_cleanup_ctx(void *data);


/*
 * The various modules aren't actually SSL implementation agnostic,
 * so provide wrappers till they are changed to do the right thing.
 *
 * In an ideal world, this section shouldn't grow any further.
 *
 * Other things that could be abstracted better are:
 * * ngx_md5 and ngx_sha1 currently rely on polarssl/openssl.h
 * * ngx_ssl_rsa512_key_callback likewise uses definitions from
 *   polarssl/openssl.h
 * * The SNI support in ngx_http_ssl_module/ngx_http_request needs
 *   to be rewritten since it's too painful to try to provide wrappers.
 */

#define X509                                    x509_cert
#define X509_V_OK                               0
#define SSL_OP_CIPHER_SERVER_PREFERENCE         0x1

int SSL_CTX_set_cipher_list(void *ctx, const char *ciphers);
long SSL_CTX_set_options(void *ctx, long options);
void SSL_CTX_set_tmp_rsa_callback(void *ctx,
    RSA *(*tmp_rsa_callback)(SSL *ssl, int is_export, int keylength));
void *SSL_get0_session(const SSL *ssl);
long SSL_get_verify_result(const SSL *ssl);

X509 *SSL_get_peer_certificate(SSL *ssl);
const char *X509_verify_cert_error_string(long n);
void X509_free(X509 *cert);

#endif /* _NGX_EVENT_POLARSSL_H_INCLUDED_ */
